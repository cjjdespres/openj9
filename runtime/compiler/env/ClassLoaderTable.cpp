/*******************************************************************************
 * Copyright IBM Corp. and others 2000
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

#include "AtomicSupport.hpp"
#include "control/CompilationThread.hpp"
#include "control/OMROptions.hpp"
#include "env/ClassLoaderTable.hpp"
#include "env/J9PersistentInfo.hpp"
#include "env/J9SharedCache.hpp"
#include "env/PersistentCollections.hpp"
#include "env/VerboseLog.hpp"
#include "env/jittypes.h"
#include "infra/MonitorTable.hpp"
#include <cstdint>


enum TableKind { Loader, Chain, Name };

// To make the three-way map between class loaders, class chains, and class names more efficient, this
// struct is linked into three linked lists - one for each hash table in TR_PersistentClassLoaderTable.
struct TR_ClassLoaderInfo
   {
   TR_PERSISTENT_ALLOC(TR_Memory::PersistentCHTable)

   TR_ClassLoaderInfo(void *loader, void *chain, J9UTF8 *nameStr) :
      _loader(loader), _loaderTableNext(NULL),
      _chain(chain), _chainTableNext(NULL)
#if defined(J9VM_OPT_JITSERVER)
      , _nameStr(nameStr), _nameTableNext(NULL)
#endif /* defined(J9VM_OPT_JITSERVER) */
      { }

#if defined(J9VM_OPT_JITSERVER)
   const J9UTF8 *name() const
      {
      return _nameStr;
      }
#endif /* defined(J9VM_OPT_JITSERVER) */

   template<TableKind T> TR_ClassLoaderInfo *&next();
   template<TableKind T> bool equals(const void *key) const;

   void *const _loader;
   TR_ClassLoaderInfo *_loaderTableNext;
   void *const _chain;
   TR_ClassLoaderInfo *_chainTableNext;
#if defined(J9VM_OPT_JITSERVER)
   TR_ClassLoaderInfo *_nameTableNext;
   // The ROM class name will either be in the local SCC or will be
   // copied to persistent memory managed by this loader info entry.
   // It is also tracked only if we might be a client of a JITServer
   // AOT cache.
   J9UTF8 *_nameStr;
#endif /* defined(J9VM_OPT_JITSERVER) */
   };

// Create a persistent copy of the given string
static J9UTF8 *
copyJ9UTF8(const J9UTF8 *nameStr, TR_PersistentMemory *persistentMemory)
   {
   size_t nameSize = J9UTF8_TOTAL_SIZE(nameStr);

   void *ptr = persistentMemory->allocatePersistentMemory(nameSize);
   if (!ptr)
      return NULL;

   memcpy(ptr, nameStr, nameSize);
   return (J9UTF8 *)ptr;
   }

template<TableKind T> static size_t hash(const void *key);

template<TableKind T> static TR_ClassLoaderInfo *
lookup(TR_ClassLoaderInfo *const *table, size_t &index, TR_ClassLoaderInfo *&prev, const void *key)
   {
   index = hash<T>(key) % CLASSLOADERTABLE_SIZE;
   TR_ClassLoaderInfo *info = table[index];
   prev = NULL;
   while (info && !info->equals<T>(key))
      {
      prev = info;
      info = info->next<T>();
      }
   return info;
   }

template<TableKind T> static void
insert(TR_ClassLoaderInfo *info, TR_ClassLoaderInfo **table, size_t index)
   {
   info->next<T>() = table[index];
   // Write barrier guarantees that a reader thread traversing the list will read
   // the new list head only after its next field is already set to the old head.
   VM_AtomicSupport::writeBarrier();
   table[index] = info;
   }

template<TableKind T> static void
remove(TR_ClassLoaderInfo *info, TR_ClassLoaderInfo *prev, TR_ClassLoaderInfo **table, size_t index)
   {
   if (prev)
      prev->next<T>() = info->next<T>();
   else
      table[index] = info->next<T>();
   }


template<> TR_ClassLoaderInfo *&TR_ClassLoaderInfo::next<Loader>() { return _loaderTableNext; }
template<> bool TR_ClassLoaderInfo::equals<Loader>(const void *loader) const { return loader == _loader; }
// Remove trailing zero bits in aligned pointer for better hash distribution
template<> size_t hash<Loader>(const void *loader) { return (uintptr_t)loader >> 3; }

template<> TR_ClassLoaderInfo *&TR_ClassLoaderInfo::next<Chain>() { return _chainTableNext; }
template<> bool TR_ClassLoaderInfo::equals<Chain>(const void *chain) const { return chain == _chain; }
// Remove trailing zero bits in aligned pointer for better hash distribution
template<> size_t hash<Chain>(const void *chain) { return (uintptr_t)chain >> 3; }


#if defined(J9VM_OPT_JITSERVER)

template<> TR_ClassLoaderInfo *&TR_ClassLoaderInfo::next<Name>() { return _nameTableNext; }

struct NameKey
   {
   const uint8_t *_data;
   size_t _length;
   };

template<> bool
TR_ClassLoaderInfo::equals<Name>(const void *keyPtr) const
   {
   auto key = (const NameKey *)keyPtr;
   const J9UTF8 *str = name();
   return J9UTF8_DATA_EQUALS(J9UTF8_DATA(str), J9UTF8_LENGTH(str), key->_data, key->_length);
   }

template<> size_t
hash<Name>(const void *keyPtr)
   {
   auto key = (const NameKey *)keyPtr;
   size_t h = 0;
   for (size_t i = 0; i < key->_length; ++i)
      h = (h << 5) - h + key->_data[i];
   return h;
   }

#endif /* defined(J9VM_OPT_JITSERVER) */


TR_PersistentClassLoaderTable::TR_PersistentClassLoaderTable(TR_PersistentMemory *persistentMemory) :
   _persistentMemory(persistentMemory), _sharedCache(NULL)
   {
   memset(_loaderTable, 0, sizeof(_loaderTable));
   memset(_chainTable, 0, sizeof(_chainTable));
#if defined(J9VM_OPT_JITSERVER)
   memset(_nameTable, 0, sizeof(_nameTable));
#endif /* defined(J9VM_OPT_JITSERVER) */
   }


//NOTE: Class loader table doesn't require any additional locking for synchronization.
// Writers are always mutually exclusive with each other. Readers cannot be concurrent
// with the writers that remove entries from the table. Traversing linked lists in hash
// buckets can be concurrent with inserting new entries (which only needs a write barrier).

static bool
hasSharedVMAccess(J9VMThread *vmThread)
   {
   return (vmThread->publicFlags & J9_PUBLIC_FLAGS_VM_ACCESS) && !vmThread->omrVMThread->exclusiveCount;
   }


void
TR_PersistentClassLoaderTable::associateClassLoaderWithClass(J9VMThread *vmThread, void *loader,
                                                             TR_OpaqueClassBlock *clazz)
   {
   // Since current thread has shared VM access and holds the classTableMutex,
   // no other thread can be modifying the table at the same time.
   TR_ASSERT(hasSharedVMAccess(vmThread), "Must have shared VM access");
   TR_ASSERT(TR::MonitorTable::get()->getClassTableMutex()->owned_by_self(), "Must hold classTableMutex");

   bool useAOTCache = false;
#if defined(J9VM_OPT_JITSERVER)
   useAOTCache = _persistentMemory->getPersistentInfo()->getJITServerUseAOTCache();
#endif /* defined(J9VM_OPT_JITSERVER) */

   if (!_sharedCache && !useAOTCache)
      return;

   // Lookup by class loader and check if it already has an associated class
   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Loader>(_loaderTable, index, prev, loader);
   if (info)
      return;

#if defined(J9VM_OPT_JITSERVER)
   auto romClass = ((J9Class *)clazz)->romClass;
   auto romName = J9ROMCLASS_CLASSNAME(romClass);
   const uint8_t *name = J9UTF8_DATA(romName);
   size_t nameLength = J9UTF8_LENGTH(romName);
#endif /* defined(J9VM_OPT_JITSERVER) */

   void *chain = NULL;
   if (_sharedCache)
      {
      uintptr_t chainOffset = _sharedCache->rememberClass(clazz);
      if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET == chainOffset)
         {
#if defined(J9VM_OPT_JITSERVER)
         if (useAOTCache && TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
               "ERROR: Failed to get class chain for %.*s loaded by %p",
               nameLength, (const char *)name, loader
            );
#endif /* defined(J9VM_OPT_JITSERVER) */
         }
      else
         {
         chain = _sharedCache->pointerFromOffsetInSharedCache(chainOffset);
         TR_ASSERT(_sharedCache->isPointerInSharedCache(chain), "Class chain must be in SCC");
         }
      }

   J9UTF8 *nameStr = NULL;
#if defined(J9VM_OPT_JITSERVER)
   if (useAOTCache)
      {
      nameStr = (_sharedCache && _sharedCache->isROMClassInSharedCache(romClass)) ? romName : copyJ9UTF8(romName, _persistentMemory);
      }
#endif /* defined(J9VM_OPT_JITSERVER) */

   // If we could not retrieve a chain for the class and could not retrieve a name for the class, then
   // there is no point in continuing.
   if (!chain && !nameStr)
      return;
   TR_ASSERT(!_sharedCache || !chain || _sharedCache->isPointerInSharedCache(chain), "Class chain must be in SCC");

   info = new (_persistentMemory) TR_ClassLoaderInfo(loader, chain, nameStr);
   if (!info)
      {
      // This is a bad situation because we can't associate the right class with this class loader.
      // Probably not critical if multiple class loaders aren't routinely loading the exact same class.
      //TODO: Prevent this class loader from associating with a different class
#if defined(J9VM_OPT_JITSERVER)
      if (useAOTCache && TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
            "ERROR: Failed to associate class %.*s chain %p with loader %p",
            nameLength, (const char *)name, chain, loader
         );
#endif /* defined(J9VM_OPT_JITSERVER) */
      return;
      }
   insert<Loader>(info, _loaderTable, index);

   // Lookup by class chain and check if was already associated with another class loader
   if (chain)
      {
      TR_ClassLoaderInfo *otherInfo = lookup<Chain>(_chainTable, index, prev, chain);
      if (otherInfo)
         {
         // There is more than one class loader with identical first loaded class.
         // Current heuristic doesn't work in this scenario, but it doesn't break
         // correctness, and in the worst case can only result in failed AOT loads.
         // We have added this loader to _classLoaderTable, which has a nice side
         // benefit that we won't keep trying to add it, so leave it there.
#if defined(J9VM_OPT_JITSERVER)
         if (useAOTCache && TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
               "ERROR: Class %.*s chain %p already associated with loader %p != %p",
               nameLength, (const char *)name, chain, otherInfo->_loader, loader
            );
#endif /* defined(J9VM_OPT_JITSERVER) */
         return;
         }
      insert<Chain>(info, _chainTable, index);
      }

#if defined(J9VM_OPT_JITSERVER)
   if (nameStr)
      {
      // Lookup by class name and check if it was already associated with another class loader
      NameKey key { name, nameLength };
      TR_ClassLoaderInfo *otherInfo = lookup<Name>(_nameTable, index, prev, &key);
      if (otherInfo)
         {
         // There is more than one class loader with the same name of the first loaded
         // class (but the classes themselves are not identical). Current AOT cache
         // heuristic doesn't work in this scenario, but it doesn't break correctness,
         // and in the worst case can only result in failed AOT method deserialization.
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
               "ERROR: Class name %.*s already associated with loader %p != %p",
               nameLength, (const char *)name, otherInfo->_loader, loader
            );
         return;
         }
      insert<Name>(info, _nameTable, index);

      if (TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
            "Associated class loader %p with class %.*s chain %p",
            loader, nameLength, (const char *)name, chain
         );
      }
#endif /* defined(J9VM_OPT_JITSERVER) */
   }


static void
assertCurrentThreadCanRead()
   {
   // To guarantee that reading the table is not concurrent with class loader removal during GC,
   // current thread must either have shared VM access or hold the classUnloadMonitor for reading.
#if defined(DEBUG) || defined(PROD_WITH_ASSUMES)
   TR::Compilation *comp = TR::comp();
   TR_ASSERT(hasSharedVMAccess(comp->j9VMThread()) ||
             (TR::MonitorTable::get()->getClassUnloadMonitorHoldCount(comp->getCompThreadID()) > 0),
             "Must either have shared VM access of hold classUnloadMonitor for reading");
#endif /* defined(DEBUG) || defined(PROD_WITH_ASSUMES) */
   }

void *
TR_PersistentClassLoaderTable::lookupClassChainAssociatedWithClassLoader(void *loader) const
   {
   assertCurrentThreadCanRead();
   if (!_sharedCache)
      return NULL;

   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Loader>(_loaderTable, index, prev, loader);
   return info ? info->_chain : NULL;
   }

void *
TR_PersistentClassLoaderTable::lookupClassLoaderAssociatedWithClassChain(void *chain) const
   {
   assertCurrentThreadCanRead();
   if (!_sharedCache)
      return NULL;

   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Chain>(_chainTable, index, prev, chain);
   return info ? info->_loader : NULL;
   }

#if defined(J9VM_OPT_JITSERVER)

std::pair<void *, void *>
TR_PersistentClassLoaderTable::lookupClassLoaderAndChainAssociatedWithClassName(const uint8_t *data, size_t length) const
   {
   assertCurrentThreadCanRead();

   NameKey key { data, length };
   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Name>(_nameTable, index, prev, &key);
   if (!info)
      return { NULL, NULL };
   return { info->_loader, info->_chain };
   }

void *
TR_PersistentClassLoaderTable::lookupClassLoaderAssociatedWithClassName(const uint8_t *data, size_t length) const
   {
   assertCurrentThreadCanRead();

   NameKey key { data, length };
   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Name>(_nameTable, index, prev, &key);
   if (!info)
      return NULL;
   return info->_loader;
   }

const J9UTF8 *
TR_PersistentClassLoaderTable::lookupClassNameAssociatedWithClassLoader(void *loader) const
   {
   assertCurrentThreadCanRead();

   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Loader>(_loaderTable, index, prev, loader);
   if (!info)
      return NULL;
   return info->_nameStr;
   }
#endif /* defined(J9VM_OPT_JITSERVER) */


void
TR_PersistentClassLoaderTable::removeClassLoader(J9VMThread *vmThread, void *loader)
   {
   // Since current thread has exclusive VM access and holds the classUnloadMonitor
   // for writing (NOTE: we don't have an assertion for that due to lack of API),
   // no other thread can be modifying the table at the same time.
   TR_ASSERT((vmThread->publicFlags & J9_PUBLIC_FLAGS_VM_ACCESS) && vmThread->omrVMThread->exclusiveCount,
             "Must have exclusive VM access");

   bool useAOTCache = false;
#if defined(J9VM_OPT_JITSERVER)
   useAOTCache = _persistentMemory->getPersistentInfo()->getJITServerUseAOTCache();
#endif /* defined(J9VM_OPT_JITSERVER) */

   if (!_sharedCache && !useAOTCache)
      return;

   // Remove from the table indexed by class loader
   size_t index;
   TR_ClassLoaderInfo *prev;
   TR_ClassLoaderInfo *info = lookup<Loader>(_loaderTable, index, prev, loader);
   if (!info)
      return;
   remove<Loader>(info, prev, _loaderTable, index);

   // Remove from the table indexed by class chain
   if (info->_chain)
      {
      TR_ClassLoaderInfo *otherInfo = lookup<Chain>(_chainTable, index, prev, info->_chain);
      if (otherInfo == info)// Otherwise the entry belongs to another class loader
         remove<Chain>(info, prev, _chainTable, index);
      }

#if defined(J9VM_OPT_JITSERVER)
   if (useAOTCache)
      {
      // Remove from the table indexed by class name
      J9UTF8 *nameStr = info->_nameStr;
      const uint8_t *name = J9UTF8_DATA(nameStr);
      uint16_t nameLength = J9UTF8_LENGTH(nameStr);

      NameKey key { name, nameLength };
      TR_ClassLoaderInfo *otherInfo = lookup<Name>(_nameTable, index, prev, &key);
      if (otherInfo == info)// Otherwise the entry belongs to another class loader
         remove<Name>(info, prev, _nameTable, index);

      if (TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer,
            "Removed class loader %p associated with class %.*s chain %p",
            loader, nameLength, (const char *)name, info->_chain
         );

      if (!_sharedCache || !_sharedCache->isPtrToROMClassesSectionInSharedCache(nameStr))
         _persistentMemory->freePersistentMemory(nameStr);
      }
#endif /* defined(J9VM_OPT_JITSERVER) */

   _persistentMemory->freePersistentMemory(info);
   }

TR_AOTDependencyTable::TR_AOTDependencyTable(TR_PersistentMemory *persistentMemory) :
   _persistentMemory(persistentMemory), _sharedCache(NULL),
   _tableMonitor(TR::Monitor::create("JIT-AOTDependencyTableMonitor")),
   _offsetMap(decltype(_offsetMap)::allocator_type(TR::Compiler->persistentAllocator())),
   _methodMap(decltype(_methodMap)::allocator_type(TR::Compiler->persistentAllocator())),
   _classMap(decltype(_classMap)::allocator_type(TR::Compiler->persistentAllocator()))
   {
   }

void
TR_AOTDependencyTable::trackStoredMethod(J9VMThread *vmThread, J9Method *method, const uintptr_t *dependencyChain)
   {
   uintptr_t dependencyChainLength = *dependencyChain;
   const uintptr_t *dependencyChainData = dependencyChain + 1;

   // TODO: verbose option
   J9UTF8 *className = J9ROMCLASS_CLASSNAME(J9_CLASS_FROM_METHOD(method)->romClass);
   J9UTF8 *name      = J9ROMMETHOD_NAME(J9_ROM_METHOD_FROM_RAM_METHOD(method));
   J9UTF8 *signature = J9ROMMETHOD_SIGNATURE(J9_ROM_METHOD_FROM_RAM_METHOD(method));
   if (TR::Options::getVerboseOption(TR_VerbosePerformance))
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Tracking method in local SCC with %lu: %.*s.%.*s%.*s",
                                     dependencyChainLength,
                                     J9UTF8_LENGTH(className), J9UTF8_DATA(className),
                                     J9UTF8_LENGTH(name), J9UTF8_DATA(name),
                                     J9UTF8_LENGTH(signature), J9UTF8_DATA(signature));

   OMR::CriticalSection cs(_tableMonitor);

   // TODO: checking?
   uintptr_t *methodCount = &_methodMap.insert({method, {0, dependencyChain}}).first->second._dependencyCount;

   uintptr_t numberRemainingDependencies = dependencyChainLength;

   // TODO: sanity checking here!
   for (size_t i = 0; i < dependencyChainLength; ++i)
      {
      uintptr_t offset = dependencyChainData[i];
      TR_ASSERT_FATAL(_sharedCache->isOffsetInCache(offset), "Offset must be in the SCC!");
      auto it = _offsetMap.find(offset);
      if (it == _offsetMap.end())
         {
         // TODO probably incorrectly allocated
         PersistentUnorderedSet<uintptr_t *> waitingCounts(PersistentUnorderedSet<uintptr_t *>::allocator_type(TR::Compiler->persistentAllocator()));
         it = _offsetMap.insert(it, {offset, {0, waitingCounts}});
         }
      auto &offsetEntry = it->second;
      offsetEntry._waitingMethodCounts.insert(methodCount);
      if (offsetEntry._loadedClassCount > 0)
         numberRemainingDependencies -= 1;
      }

   // TODO: assert is still non-neg.
   if (numberRemainingDependencies == 0)
      {
      stopTracking(method);
      queueAOTLoad(method);
      }
   else
      {
      *methodCount = numberRemainingDependencies;
      }
   }

void
TR_AOTDependencyTable::onClassLoad(TR_OpaqueClassBlock *clazz)
   {
   OMR::CriticalSection cs(_tableMonitor);

   auto ramClass = (J9Class *)clazz;

   uintptr_t classOffset = TR_J9SharedCache::INVALID_ROM_CLASS_OFFSET;
   if (!_sharedCache->isClassInSharedCache(ramClass, &classOffset))
      return;
   registerOffset(classOffset);

   uintptr_t chainOffset = _sharedCache->rememberClass(ramClass, NULL, false);
   if (chainOffset != TR_J9SharedCache::INVALID_CLASS_CHAIN_OFFSET)
      registerOffset(chainOffset);

   _classMap.insert({ramClass, {classOffset, chainOffset}});

   if (TR::Options::getVerboseOption(TR_VerbosePerformance))
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Tracking class: %p %lu %lu", ramClass, classOffset, chainOffset);
   }

void
TR_AOTDependencyTable::registerOffset(uintptr_t offset)
   {
   // TODO: duplication with tracking above! (registerOffset should just take an initial loaded count and return a pointer to the resulting entry)
   auto it = _offsetMap.find(offset);
   if (it == _offsetMap.end())
      {
      // TODO probably incorrectly allocated
      PersistentUnorderedSet<uintptr_t *> waitingCounts(PersistentUnorderedSet<uintptr_t *>::allocator_type(TR::Compiler->persistentAllocator()));
      it = _offsetMap.insert(it, {offset, {0, waitingCounts}});
      }
   auto &offsetEntry = it->second;
   offsetEntry._loadedClassCount += 1;
   }

void
TR_AOTDependencyTable::invalidateClass(TR_OpaqueClassBlock *clazz)
   {
   OMR::CriticalSection cs(_tableMonitor);

   auto ramClass = (J9Class *)clazz;

   auto c_it = _classMap.find(ramClass);
   if (c_it == _classMap.end())
      return;

   unregisterOffset(c_it->second._classChainOffset);
   unregisterOffset(c_it->second._classOffset);

   _classMap.erase(c_it);
   if (TR::Options::getVerboseOption(TR_VerbosePerformance))
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Invalidated dependency class %p", ramClass);
   }

void
TR_AOTDependencyTable::unregisterOffset(uintptr_t offset)
   {
   auto it = _offsetMap.find(offset);
   if ((it == _offsetMap.end()) || (it->second._loadedClassCount == 0))
      return;

   it->second._loadedClassCount -= 1;
   for (auto count : it->second._waitingMethodCounts)
      ++(*count);
   }

void
TR_AOTDependencyTable::stopTracking(J9Method *method)
   {
   auto m_it = _methodMap.find(method);
   if (m_it == _methodMap.end())
      return;

   auto dependencyCount = &m_it->second._dependencyCount;
   auto dependencyChain = m_it->second._dependencyChain;
   auto dependencyChainLength = *dependencyChain;
   auto dependencyChainData = dependencyChain + 1;

   for (size_t i = 0; i < dependencyChainLength; ++i)
      {
      auto m_it = _offsetMap.find(dependencyChainData[i]);
      TR_ASSERT_FATAL(m_it != _offsetMap.end(), "Offset of method %p cannot be untracked!", method);
      m_it->second._waitingMethodCounts.erase(dependencyCount);
      }

   _methodMap.erase(m_it);
   }

void
TR_AOTDependencyTable::queueAOTLoad(J9Method *method)
   {
   auto count = _sharedCache->fe()->getInvocationCount((TR_OpaqueMethodBlock *)method);
   if (TR::Options::getVerboseOption(TR_VerbosePerformance))
      TR_VerboseLog::writeLineLocked(TR_Vlog_INFO, "Would have triggered load of %p at count %d", method, count);
   }
