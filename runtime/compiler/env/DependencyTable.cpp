/*******************************************************************************
 * Copyright IBM Corp. and others 2024
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] https://openjdk.org/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-2.0-only WITH OpenJDK-assembly-exception-1.0
 *******************************************************************************/

#include "control/CompilationRuntime.hpp"
#include "control/CompilationThread.hpp"
#include "env/ClassLoaderTable.hpp"
#include "env/DependencyTable.hpp"
#include "env/J9SharedCache.hpp"
#include "env/PersistentCHTable.hpp"
#include "j9.h"

#if !defined(PERSISTENT_COLLECTIONS_UNSUPPORTED)

TR_AOTDependencyTable::TR_AOTDependencyTable(TR_J9SharedCache *sharedCache) :
   _isActive(true),
   _sharedCache(sharedCache),
   _tableMonitor(TR::Monitor::create("JIT-AOTDependencyTableMonitor")),
   _offsetMap(decltype(_offsetMap)::allocator_type(TR::Compiler->persistentAllocator())),
   _methodMap(decltype(_methodMap)::allocator_type(TR::Compiler->persistentAllocator())),
   _pendingLoads(decltype(_pendingLoads)::allocator_type(TR::Compiler->persistentAllocator()))
   { }

bool
TR_AOTDependencyTable::trackMethod(J9VMThread *vmThread, J9Method *method, J9ROMMethod *romMethod, bool &dependenciesSatisfied)
   {
   const uintptr_t *methodDependencies = NULL;
   if (!_sharedCache->methodHasAOTBodyWithDependencies(vmThread, romMethod, methodDependencies))
      return false;

   if (!methodDependencies)
      {
      dependenciesSatisfied = true;
      return true;
      }

   OMR::CriticalSection cs(_tableMonitor);
   if (!isActive())
      return false;

   try
      {
      uintptr_t totalDependencies = *methodDependencies;
      uintptr_t numberRemainingDependencies = totalDependencies;

      auto m_it = _methodMap.insert({method, {0, methodDependencies}});
      auto methodEntry = &(*m_it.first);

      for (size_t i = 1; i <= totalDependencies; ++i)
         {
         bool needsInitialization = false;
         uintptr_t chainOffset = decodeDependencyOffset(methodDependencies[i], needsInitialization);
         auto classChain = (const uintptr_t *)_sharedCache->pointerFromOffsetInSharedCache(chainOffset);
         uintptr_t offset = _sharedCache->startingROMClassOffsetOfClassChain(_sharedCache->pointerFromOffsetInSharedCache(chainOffset));
         auto entry = getOrCreateOffsetEntry(offset, classChain);
         if (needsInitialization)
            entry->_waitingInitMethods.insert(methodEntry);
         else
            entry->_waitingLoadMethods.insert(methodEntry);

         if (findCandidateForDependency(entry->_loadedClasses, needsInitialization))
            numberRemainingDependencies -= 1;
         }

      if (numberRemainingDependencies == 0)
         {
         stopTracking(methodEntry);
         dependenciesSatisfied = true;
         }
      else
         {
         methodEntry->second._remainingDependencies = numberRemainingDependencies;
         }
      }
   catch (std::exception&)
      {
      deactivateTable();
      return false;
      }

   return true;
   }

void
TR_AOTDependencyTable::methodWillBeCompiled(J9Method *method)
   {
   OMR::CriticalSection cs(_tableMonitor);
   if (!isActive())
      return;

   // TODO: For now we simply stop tracking method if for some reason a
   // compilation is triggered for it, but if the compilation in question is an
   // AOT load we might consider preventing the load from taking place (by
   // increasing the counts and continuing to track the method, or marking the
   // method as ineligible for loads and giving up on tracking it).
   stopTracking(method);
   }

void
TR_AOTDependencyTable::stopTracking(MethodEntryRef entry)
   {
   auto methodEntry = entry->second;
   auto dependencyChain = methodEntry._dependencyChain;
   auto dependencyChainLength = *dependencyChain;

   for (size_t i = 1; i <= dependencyChainLength; ++i)
      {
      bool needsInitialization = false;
      uintptr_t chainOffset = decodeDependencyOffset(dependencyChain[i], needsInitialization);
      uintptr_t offset = _sharedCache->startingROMClassOffsetOfClassChain(_sharedCache->pointerFromOffsetInSharedCache(chainOffset));

      auto o_it = _offsetMap.find(offset);

      if (needsInitialization)
         o_it->second._waitingInitMethods.erase(entry);
      else
         o_it->second._waitingLoadMethods.erase(entry);

      eraseOffsetEntryIfEmpty(o_it->second, offset);
      }

   _methodMap.erase(entry->first);
   }

void
TR_AOTDependencyTable::stopTracking(J9Method *method)
   {
   auto entry = _methodMap.find(method);
   if (entry != _methodMap.end())
      stopTracking(&*entry);
   }

void
TR_AOTDependencyTable::eraseOffsetEntryIfEmpty(const OffsetEntry &entry, uintptr_t offset)
   {
   if (entry._loadedClasses.empty() && entry._waitingInitMethods.empty() && entry._waitingLoadMethods.empty())
      _offsetMap.erase(offset);
   }

void
TR_AOTDependencyTable::classLoadEvent(TR_OpaqueClassBlock *clazz, bool isClassLoad, bool isClassInitialization)
   {
   auto ramClass = (J9Class *)clazz;

   if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
      {
      auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table: class load event %p %.*s %d %d",
                                     ramClass, J9UTF8_LENGTH(name), J9UTF8_DATA(name), isClassLoad, isClassInitialization);

      }

   uintptr_t classOffset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
   if (!_sharedCache->isClassInSharedCache(clazz, &classOffset))
      return;

   if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
      {
      auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table: class %p rom offset %lu",
                                     ramClass, classOffset);
      }

   // We only need to check if clazz matches its cached version on load; on
   // initialization, it will be in the _offsetMap if it did match.
   uintptr_t classChainOffset = TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET;
   const uintptr_t *classChain = NULL;
   if (isClassLoad)
      {
      classChainOffset = _sharedCache->rememberClassNoCache(ramClass, NULL, true, &classChain);
      if (!classChain)
         return;
      }

   if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
      {
      auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table: class %p chain %p %lu",
                                     ramClass, classChain, classOffset);
      }

   OMR::CriticalSection cs(_tableMonitor);
   if (!isActive())
      return;

   try
      {
      classLoadEventAtOffset(ramClass, classOffset, classChain, isClassLoad, isClassInitialization);
      }
   catch (std::exception&)
      {
      deactivateTable();
      return;
      }

   resolvePendingLoads();
   }

void
TR_AOTDependencyTable::registerSatisfaction(PersistentUnorderedSet<MethodEntryRef> waitingMethods)
   {
   for (auto &entry: waitingMethods)
      {
      if (entry->second._remainingDependencies == 1)
         _pendingLoads.insert(entry);
      else
         --entry->second._remainingDependencies;
      }
   }

void
TR_AOTDependencyTable::classLoadEventAtOffset(J9Class *ramClass, uintptr_t offset, const uintptr_t *classChain, bool isClassLoad, bool isClassInitialization)
   {
   auto offsetEntry = isClassLoad ? getOrCreateOffsetEntry(offset, classChain) : getOffsetEntry(offset);

   // We only need to check for chain validity on load, because for
   // initialization (that isn't a simultaneous load) we can simply check to see
   // if ramClass is already tracked and abort the update if not.
   if (!offsetEntry)
      return;
   if (!isClassLoad && (offsetEntry->_loadedClasses.find(ramClass) == offsetEntry->_loadedClasses.end()))
      return;

   // Check for dependency satisfaction if this is the first class initialized
   // for this offset.
   if (isClassInitialization)
      {
      // TODO: need to confirm that ramClass->initializeStatus will never itself
      // be J9ClassInitSucceeded, in which case the loop below can be replaced
      // with !findCandidateForDependency()
      bool existingInit = false;
      for (const auto& entry: offsetEntry->_loadedClasses)
         {
         if ((J9ClassInitSucceeded == entry->initializeStatus) && (entry != ramClass))
            {
            existingInit = true;
            break;
            }
         }
      if (!existingInit)
         registerSatisfaction(offsetEntry->_waitingInitMethods);
      }

   // Track the class, and also check for dependency satisfaction if this is the
   // first class loaded for this offset
   if (isClassLoad)
      {
      if (!findCandidateForDependency(offsetEntry->_loadedClasses, false))
         registerSatisfaction(offsetEntry->_waitingLoadMethods);
      offsetEntry->_loadedClasses.insert(ramClass);
      }
   }

OffsetEntry *
TR_AOTDependencyTable::getOffsetEntry(uintptr_t offset)
   {
   auto it = _offsetMap.find(offset);
   if (it != _offsetMap.end())
      return &it->second;

   return NULL;
   }

OffsetEntry *
TR_AOTDependencyTable::getOrCreateOffsetEntry(uintptr_t romClassOffset, const uintptr_t *classChain)
   {
   auto it = _offsetMap.find(romClassOffset);
   if (it != _offsetMap.end())
      return &it->second;

   PersistentUnorderedSet<J9Class *> loadedClasses(PersistentUnorderedSet<J9Class *>::allocator_type(TR::Compiler->persistentAllocator()));
   PersistentUnorderedSet<MethodEntryRef> waitingLoadMethods(PersistentUnorderedSet<MethodEntryRef>::allocator_type(TR::Compiler->persistentAllocator()));
   PersistentUnorderedSet<MethodEntryRef> waitingInitMethods(PersistentUnorderedSet<MethodEntryRef>::allocator_type(TR::Compiler->persistentAllocator()));
   return &(*_offsetMap.insert(it, {romClassOffset, {classChain, loadedClasses, waitingLoadMethods, waitingInitMethods}})).second;
   }

void
TR_AOTDependencyTable::invalidateUnloadedClass(TR_OpaqueClassBlock *clazz)
   {
   uintptr_t classOffset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
   if (!_sharedCache->isClassInSharedCache(clazz, &classOffset))
      return;


   OMR::CriticalSection cs(_tableMonitor);
   if (!isActive())
      return;

   auto ramClass = (J9Class *)clazz;
   if (invalidateClassAtOffset(ramClass, classOffset))
      invalidateMethodsOfClass(ramClass);
   }

void
TR_AOTDependencyTable::registerDissatisfaction(PersistentUnorderedSet<MethodEntryRef> waitingMethods)
   {
   for (auto& entry: waitingMethods)
      {
      ++entry->second._remainingDependencies;
      _pendingLoads.erase(entry);
      }
   }

bool
TR_AOTDependencyTable::invalidateClassAtOffset(J9Class *ramClass, uintptr_t romClassOffset)
   {
   auto entry = getOffsetEntry(romClassOffset);
   if (entry)
      {
      entry->_loadedClasses.erase(ramClass);

      // Update the waiting methods if the removal of ramClass caused a
      // dependency to become unsatisfied
      if (entry->_loadedClasses.empty())
         {
         registerDissatisfaction(entry->_waitingLoadMethods);
         registerDissatisfaction(entry->_waitingInitMethods);
         eraseOffsetEntryIfEmpty(*entry, romClassOffset);
         }
      else if (!findCandidateForDependency(entry->_loadedClasses, true))
         {
         registerDissatisfaction(entry->_waitingInitMethods);
         }

      return true;
      }

   return false;
   }

void
TR_AOTDependencyTable::invalidateMethodsOfClass(J9Class *ramClass)
   {
   for (uint32_t i = 0; i < ramClass->romClass->romMethodCount; i++)
      stopTracking(&ramClass->ramMethods[i]);
   }

// If an entry exists for a class, remove it. Otherwise, if we should
// revalidate, add an entry if the class has a valid chain.
void
TR_AOTDependencyTable::recheckSubclass(J9Class *ramClass, uintptr_t offset, bool shouldRevalidate)
   {
   if (invalidateClassAtOffset(ramClass, offset) || !shouldRevalidate)
      return;

   const uintptr_t *classChain = NULL;
   uintptr_t classChainOffset = _sharedCache->rememberClassNoCache(ramClass, NULL, true, &classChain);
   if (!classChain)
      return;

   bool initialized = J9ClassInitSucceeded == ramClass->initializeStatus;
   classLoadEventAtOffset(ramClass, offset, classChain, true, initialized);
   }

// In a class redefinition event, an old class is replaced by a fresh class. If
// the ROM class offset changed as a result, it and all its subclasses that
// formerly had valid chains will now be guaranteed not to match, so the entries
// for these must be removed. If the new offset is valid, any class that didn't
// have an entry should be rechecked.
void
TR_AOTDependencyTable::invalidateRedefinedClass(TR_PersistentCHTable *table, TR_J9VMBase *fej9, TR_OpaqueClassBlock *oldClass, TR_OpaqueClassBlock *freshClass)
   {
   uintptr_t freshClassOffset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
   uintptr_t oldClassOffset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
   if (!_sharedCache->isClassInSharedCache(freshClass, &freshClassOffset) && !_sharedCache->isClassInSharedCache(oldClass, &oldClassOffset))
      return;

   if (oldClassOffset == freshClassOffset)
      {
      OMR::CriticalSection cs(_tableMonitor);
      if (!isActive())
         return;

      try
         {
         // If the offset is unchanged and the old class was tracked, the new
         // class will have a valid chain as well, so we only need to swap the
         // old and fresh class pointers.

         // TODO: elegance, but we need to save the old offset in case the entry
         // gets deleted because of invalidation here.
         auto oldEntry = getOffsetEntry(oldClassOffset);
         auto classChain = oldEntry ? oldEntry->_classChain : NULL;
         if (invalidateClassAtOffset((J9Class *)oldClass, oldClassOffset))
            {
            invalidateMethodsOfClass((J9Class *)oldClass);
            auto freshRamClass = (J9Class *)freshClass;
            bool initialized = J9ClassInitSucceeded == freshRamClass->initializeStatus;
            classLoadEventAtOffset(freshRamClass, freshClassOffset, classChain, true, initialized);
            }
         }
      catch (std::exception&)
         {
         deactivateTable();
         return;
         }

      resolvePendingLoads();
      return;
      }

   bool revalidateUntrackedClasses = freshClassOffset != TR_SharedCache::INVALID_ROM_CLASS_OFFSET;

   TR_PersistentClassInfo *classInfo = table->findClassInfo(oldClass);
   TR_PersistentCHTable::ClassList classList(TR::Compiler->persistentAllocator());

   table->collectAllSubClasses(classInfo, classList, fej9);
   classList.push_front(classInfo);

   OMR::CriticalSection cs(_tableMonitor);
   if (!isActive())
      return;

   try
      {
      // Invalidate the methods of oldClass first, so _pendingLoads doesn't have
      // to be cleared of invalidated method entries
      invalidateMethodsOfClass((J9Class *)oldClass);
      for (auto iter = classList.begin(); iter != classList.end(); iter++)
         {
         auto clazz = (J9Class *)(*iter)->getClassId();
         uintptr_t offset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
         if (!_sharedCache->isClassInSharedCache(clazz, &offset))
            continue;
         recheckSubclass(clazz, offset, revalidateUntrackedClasses);
         }
      }
   catch (std::exception&)
      {
      deactivateTable();
      }

   resolvePendingLoads();
   }

void
TR_AOTDependencyTable::resolvePendingLoads()
   {
   for (auto& entry: _pendingLoads)
      {
      auto method = entry->first;
      auto count = TR::CompilationInfo::getInvocationCount(method);
      while ((count > 0) && !TR::CompilationInfo::setInvocationCount(method, count, 0))
         count = TR::CompilationInfo::getInvocationCount(method);
      stopTracking(entry);
      }
   _pendingLoads.clear();
   }

J9Class *
TR_AOTDependencyTable::findCandidateWithChainAndLoader(TR::Compilation *comp, uintptr_t classChainOffset, void *classLoaderChain)
   {
   TR_ASSERT(classLoaderChain, "Must be given a loader chain");

   if (comp->isDeserializedAOTMethod() || comp->ignoringLocalSCC())
      return NULL;

   void *chain = _sharedCache->pointerFromOffsetInSharedCache(classChainOffset);
   uintptr_t romClassOffset = _sharedCache->startingROMClassOffsetOfClassChain(chain);

   if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
      {
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table findCandidate: %lu %p %p %lu",
                                     classChainOffset, classLoaderChain, chain, romClassOffset);
      }

   OMR::CriticalSection cs(_tableMonitor);

   if (!isActive())
      return NULL;

   auto it = _offsetMap.find(romClassOffset);
   if (it == _offsetMap.end())
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table findCandidate: no entry %lu %p",
                                        classChainOffset,
                                        classLoaderChain);
         }

      return NULL;
      }

   // TODO: should probably unify all this for loops into a single find
   J9Class *candidate = NULL;
   for (const auto& entry : it->second._loadedClasses)
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table findCandidate: examining %p %p %p %d",
                                        entry,
                                        entry->classLoader,
                                        _sharedCache->persistentClassLoaderTable()->lookupClassChainAssociatedWithClassLoader(entry->classLoader),
                                        entry->initializeStatus);
         }

      if ((J9ClassInitSucceeded == entry->initializeStatus) &&
          (_sharedCache->persistentClassLoaderTable()->lookupClassChainAssociatedWithClassLoader(entry->classLoader) == classLoaderChain))
         {
         candidate = entry;
         break;
         }
      }

      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table findCandidate: using %p for %lu",
                                        candidate,
                                        classChainOffset);
         }

   return candidate;
   }


J9Class *
TR_AOTDependencyTable::findCandidateForDependency(const PersistentUnorderedSet<J9Class *> &loadedClasses, bool needsInitialization)
   {
   for (const auto& clazz: loadedClasses)
      {
      if (!needsInitialization || (J9ClassInitSucceeded == clazz->initializeStatus))
         return clazz;
      }

   return NULL;
   }

uintptr_t
TR_AOTDependencyTable::getChainOffsetOfClass(TR_OpaqueClassBlock *clazz)
   {
   auto ramClass = (J9Class *)clazz;
   uintptr_t romClassOffset = TR_SharedCache::INVALID_ROM_CLASS_OFFSET;
   static bool strictChecking = feGetEnv("TR_DependencyTableStrictChecking") != NULL;
   static bool noStrictChecking = !strictChecking;

   if (!_sharedCache->isClassInSharedCache(clazz, &romClassOffset))
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table chainOffset: %p %.*s isn't in SCC",
                                        ramClass, J9UTF8_LENGTH(name), J9UTF8_DATA(name));
         }

      return TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET;
      }


   OMR::CriticalSection cs(_tableMonitor);
   auto entry = getOffsetEntry(romClassOffset);
   if (!entry)
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table chainOffset: %p %.*s %lu has no entry",
                                        ramClass, J9UTF8_LENGTH(name), J9UTF8_DATA(name), romClassOffset);
         }

      TR_ASSERT_FATAL(noStrictChecking || !_sharedCache->classMatchesCachedVersion(ramClass, NULL, false), "Class %p somehow validated!");

      return TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET;
      }

   auto it = entry->_loadedClasses.find((J9Class *)clazz);
   if (it == entry->_loadedClasses.end())
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
         {
         auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
         TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table chainOffset: %p %.*s %lu not in entry",
                                        ramClass, J9UTF8_LENGTH(name), J9UTF8_DATA(name), romClassOffset);
         }

      TR_ASSERT_FATAL(noStrictChecking || !_sharedCache->classMatchesCachedVersion(ramClass, NULL, false), "Class %p somehow validated!");
      return TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET;
      }

   uintptr_t chainOffset = _sharedCache->offsetInSharedCacheFromPointer((void *)entry->_classChain);
   if (TR::Options::getVerboseOption(TR_VerboseJITServerConns))
      {
      auto name = J9ROMCLASS_CLASSNAME(ramClass->romClass);
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Dependency table chainOffset: %p %.*s %lu %lu returned",
                                     ramClass, J9UTF8_LENGTH(name), J9UTF8_DATA(name), romClassOffset, chainOffset);
      }


   TR_ASSERT_FATAL(noStrictChecking || (_sharedCache->rememberClassNoCache(ramClass, NULL, false) == chainOffset), "Class %p somehow validated!");
   return chainOffset;
   }

void
TR_AOTDependencyTable::deactivateTable()
   {
   _offsetMap.clear();
   _methodMap.clear();
   _pendingLoads.clear();
   setInactive();
   }

#endif /* !defined(PERSISTENT_COLLECTIONS_UNSUPPORTED) */
