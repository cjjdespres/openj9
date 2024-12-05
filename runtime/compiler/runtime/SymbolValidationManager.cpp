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

#include <string.h>
#include "env/VMJ9.h"
#include "env/ClassLoaderTable.hpp"
#include "env/DependencyTable.hpp"
#include "env/JSR292Methods.h"
#include "env/PersistentCHTable.hpp"
#include "env/VMAccessCriticalSection.hpp"
#include "exceptions/AOTFailure.hpp"
#include "compile/J9Compilation.hpp"
#include "control/CompilationRuntime.hpp"
#include "control/CompilationThread.hpp"
#include "runtime/RelocationRuntime.hpp"
#include "runtime/SymbolValidationManager.hpp"

#if defined(J9VM_OPT_JITSERVER)
#include "runtime/JITClientSession.hpp"
#endif /* defined(J9VM_OPT_JITSERVER) */

#include "j9protos.h"


TR::SymbolValidationManager::SystemClassNotWorthRemembering
TR::SymbolValidationManager::_systemClassesNotWorthRemembering[] = {

   /* Generally, classes that inherit from java/lang/Throwable are used to indicate exception
    * conditions; as such, they are not going be important for the performance of normal mainline
    * code. Therefore, it is better for the AOT compiler to not be aware of these classes (and
    * thereby lose the ability to optimize for them) rather than risk a load failure due to a code
    * path that was unlikely to execute.
    */
   { "java/lang/Throwable", NULL, true },

   /* Newer java code is moving towards using StringBuilder. Therefore, ignoring this class
    * reduces load failures, while having minimal impact on steady state throughput.
    */
   { "java/lang/StringBuffer", NULL, false }
};

TR::SymbolValidationManager::SymbolValidationManager(TR::Region &region, TR_ResolvedMethod *compilee, TR::Compilation *comp)
   : _symbolID(FIRST_ID),
     _heuristicRegion(0),
     _region(region),
     _comp(comp),
     _vmThread(_comp->j9VMThread()),
     _fej9((TR_J9VM *)TR_J9VMBase::get(
        _vmThread->javaVM->jitConfig,
        _vmThread,
#if defined(J9VM_OPT_JITSERVER)
        TR::CompilationInfo::get()->getPersistentInfo()->getRemoteCompilationMode() == JITServer::SERVER ? TR_J9VMBase::J9_SERVER_VM :
#endif /* defined(J9VM_OPT_JITSERVER) */
        TR_J9VMBase::DEFAULT_VM)),
     _trMemory(_comp->trMemory()),
     _chTable(_comp->getPersistentInfo()->getPersistentCHTable()),
     _rootClass(compilee->classOfMethod()),
     _wellKnownClassChainOffsets(NULL),
#if defined(J9VM_OPT_JITSERVER)
     _aotCacheWellKnownClassesRecord(NULL),
#endif /* defined(J9VM_OPT_JITSERVER) */
     _symbolValidationRecords(_region),
     _alreadyGeneratedRecords(LessSymbolValidationRecord(), _region),
     _classesFromAnyCPIndex(LessClassFromAnyCPIndex(), _region),
     _valueToSymbolMap((ValueToSymbolComparator()), _region),
     _symbolToValueTable(_region),
     _seenValuesSet((SeenValuesComparator()), _region),
     _wellKnownClasses(_region),
     _loadersOkForWellKnownClasses(_region)
   {
   assertionsAreFatal(); // Acknowledge the env var whether or not assertions fail

#if defined(J9VM_OPT_JITSERVER)
   auto stream = TR::CompilationInfo::getStream();
   if (stream && _fej9->sharedCache())
      {
      // because a different VM is used here, a new Shared Cache object was created, so
      // need to update stream and compInfoPT
      // JITServer TODO: we update stream and compInfoPT in multiple places, better to change it to only one
      ((TR_J9JITServerSharedCache *) _fej9->sharedCache())->setStream(stream);
      ((TR_J9JITServerSharedCache *) _fej9->sharedCache())->setCompInfoPT(_fej9->_compInfoPT);
      }
#endif

   defineGuaranteedID(NULL, TR::SymbolType::typeOpaque);
   defineGuaranteedID(_rootClass, TR::SymbolType::typeClass);
   defineGuaranteedID(compilee->getPersistentIdentifier(), TR::SymbolType::typeMethod);

   for (int32_t i = 4; i <= 11; i++)
      {
      TR_OpaqueClassBlock *arrayClass = _fej9->getClassFromNewArrayTypeNonNull(i);
      TR_OpaqueClassBlock *component = _fej9->getComponentClassFromArrayClass(arrayClass);
      defineGuaranteedID(arrayClass, TR::SymbolType::typeClass);
      defineGuaranteedID(component, TR::SymbolType::typeClass);

      // Records relating the arrayClass and componentClass here would be
      // redundant.
      _alreadyGeneratedRecords.insert(
         new (_region) ArrayClassFromComponentClassRecord(arrayClass, component));
      }

   // Ensure that the count of classes not worth remembering is defined correctly
   static_assert(SYSTEM_CLASSES_NOT_WORTH_REMEMBERING_COUNT == sizeof(_systemClassesNotWorthRemembering) / sizeof(_systemClassesNotWorthRemembering[0]),
                 "SYSTEM_CLASSES_NOT_WORTH_REMEMBERING_COUNT doesn't match the size of _systemClassesNotWorthRemembering");

   }

#if defined(J9VM_OPT_JITSERVER)
void
TR::SymbolValidationManager::populateSystemClassesNotWorthRemembering(ClientSessionData *clientData)
   {
   // Populate the client session with classes not worth remembering
   auto classesNotWorthRemembering = clientData->getSystemClassesNotWorthRemembering();
   for (int i = 0; i < SYSTEM_CLASSES_NOT_WORTH_REMEMBERING_COUNT; ++i)
      {
      auto classNotWorthRemembering = &_systemClassesNotWorthRemembering[i];
      classesNotWorthRemembering[i] = { classNotWorthRemembering->_className, NULL, classNotWorthRemembering->_checkIsSuperClass };
      }
   }
#endif

void
TR::SymbolValidationManager::defineGuaranteedID(void *value, TR::SymbolType type)
   {
   uint16_t id = getNewSymbolID();
   _valueToSymbolMap.insert(std::make_pair(value, id));
   setValueOfSymbolID(id, value, type);
   _seenValuesSet.insert(value);
   }

bool
TR::SymbolValidationManager::isClassWorthRemembering(TR_OpaqueClassBlock *clazz)
   {
   bool worthRemembering = true;

   for (int i = 0; worthRemembering && i < SYSTEM_CLASSES_NOT_WORTH_REMEMBERING_COUNT; i++)
      {
      SystemClassNotWorthRemembering *systemClassNotWorthRemembering = getSystemClassNotWorthRemembering(i);
      if (!systemClassNotWorthRemembering->_clazz)
         {
         systemClassNotWorthRemembering->_clazz = _fej9->getSystemClassFromClassName(
                  systemClassNotWorthRemembering->_className,
                  (int32_t)strlen(systemClassNotWorthRemembering->_className));
         }

      if (systemClassNotWorthRemembering->_checkIsSuperClass)
         {
         if (systemClassNotWorthRemembering->_clazz &&
             _fej9->isSameOrSuperClass((J9Class *)systemClassNotWorthRemembering->_clazz, (J9Class *)clazz))
            {
            if (_comp->getOption(TR_TraceRelocatableDataCG))
               traceMsg(_comp, "isClassWorthRemembering: clazz %p is or inherits from %s (%p)\n",
                        clazz, systemClassNotWorthRemembering->_className, systemClassNotWorthRemembering->_clazz);

            worthRemembering = false;
            }
         }
      else
         {
         worthRemembering = (clazz != systemClassNotWorthRemembering->_clazz);
         }
      }

   return worthRemembering;
   }

TR::SymbolValidationManager::SystemClassNotWorthRemembering *
TR::SymbolValidationManager::getSystemClassNotWorthRemembering(int idx)
   {
#if defined(J9VM_OPT_JITSERVER)
   if (_comp->isOutOfProcessCompilation())
      {
      auto classesNotWorthRemembering = _fej9->_compInfoPT->getClientData()->getSystemClassesNotWorthRemembering();
      return &classesNotWorthRemembering[idx];
      }
   else
#endif
      {
      return &_systemClassesNotWorthRemembering[idx];
      }
   }

void
TR::SymbolValidationManager::populateWellKnownClasses()
   {
#define REQUIRED_WELL_KNOWN_CLASS_COUNT 0

   // Classes must have names only allowed to be defined by the bootstrap loader
   // The first REQUIRED_WELL_KNOWN_CLASS_COUNT entries are required - if any is
   // missing then the compilation will fail.
   // Number of entries must match WELL_KNOWN_CLASS_COUNT defined in
   // SymbolValidationManager.hpp
   static const char * const names[] =
      {
      "java/lang/Class",
      "java/lang/Object",
      "java/lang/Integer",
      "java/lang/Runnable",
      "java/lang/String",
      "java/lang/StringBuilder",
      "java/lang/System",
      "java/lang/ref/Reference",
      "com/ibm/jit/JITHelpers",
      };

   unsigned int includedClasses = 0;

   static_assert(
      sizeof (names) / sizeof (names[0]) == WELL_KNOWN_CLASS_COUNT,
      "wrong number of well-known class names");

   static_assert(
      CHAR_BIT * sizeof (includedClasses) >= WELL_KNOWN_CLASS_COUNT,
      "includedClasses needs >= WELL_KNOWN_CLASS_COUNT bits");

   uintptr_t classChainOffsets[1 + WELL_KNOWN_CLASS_COUNT] = {0};
   uintptr_t *classCount = &classChainOffsets[0];
   uintptr_t *nextClassChainOffset = &classChainOffsets[1];

#if defined(J9VM_OPT_JITSERVER)
   ClientSessionData *clientData = _comp->getClientData();
   bool aotCacheStore = _comp->isAOTCacheStore();
   const AOTCacheClassChainRecord *classChainRecords[WELL_KNOWN_CLASS_COUNT] = {0};
   bool missingClassChainRecords = false;
#endif /* defined(J9VM_OPT_JITSERVER) */

   for (int i = 0; i < WELL_KNOWN_CLASS_COUNT; i++)
      {
      const char *name = names[i];
      int32_t len = (int32_t)strlen(name);
      TR_OpaqueClassBlock *wkClass = _fej9->getSystemClassFromClassName(name, len);

      uintptr_t chainOffset = TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET;
      if (wkClass == NULL)
         {
         traceMsg(_comp, "well-known class %s not found\n", name);
         }
      else if (!_fej9->isPublicClass(wkClass))
         {
         traceMsg(_comp, "well-known class %s is not public\n", name);
         }
      else
         {
#if defined(J9VM_OPT_JITSERVER)
         auto recordPtr = &classChainRecords[_wellKnownClasses.size()];
         chainOffset = _fej9->sharedCache()->rememberClass(wkClass, recordPtr);
         if (aotCacheStore && !*recordPtr)
            missingClassChainRecords = true;
#else /* defined(J9VM_OPT_JITSERVER) */
         chainOffset = _fej9->sharedCache()->rememberClass(wkClass);
#endif /* defined(J9VM_OPT_JITSERVER) */
         }

      if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET == chainOffset)
         {
         traceMsg(_comp, "no class chain for well-known class %s\n", name);
         SVM_ASSERT_NONFATAL(
            i >= REQUIRED_WELL_KNOWN_CLASS_COUNT,
            "failed to remember required class %s\n",
            name);
         continue;
         }

      if (wkClass != _rootClass)
         defineGuaranteedID(wkClass, TR::SymbolType::typeClass);

      includedClasses |= 1 << i;
      _wellKnownClasses.push_back(wkClass);
      *nextClassChainOffset++ = chainOffset;
      }

   *classCount = _wellKnownClasses.size();

#if defined(J9VM_OPT_JITSERVER)
   if (clientData)
      {
      // This is an out-of-process compilation.

      // If we're ignoring the client's SCC, we can skip client consultation here
      if (aotCacheStore && clientData->useServerOffsets(_comp->getStream()))
         {
         // getWellKnownClassesRecord expects the number of well-known classes, not the number of elements in the object
         _aotCacheWellKnownClassesRecord = clientData->getWellKnownClassesRecord(classChainRecords, _wellKnownClasses.size(), includedClasses);
         // TODO: I think _wellKnownClassChainOffsets can remain NULL
         return;
         }

      // Otherwise check the cache in the client session first
      _wellKnownClassChainOffsets = clientData->getCachedWellKnownClassChainOffsets(
         includedClasses, _wellKnownClasses.size(), classChainOffsets + 1, _aotCacheWellKnownClassesRecord
      );
      if (_wellKnownClassChainOffsets)
         return;
      }
#endif /* defined(J9VM_OPT_JITSERVER) */

   _wellKnownClassChainOffsets = _fej9->sharedCache()->storeWellKnownClasses(_vmThread, classChainOffsets, 1 + _wellKnownClasses.size(), includedClasses);

#if defined(J9VM_OPT_JITSERVER)
   if (_wellKnownClassChainOffsets && clientData)
      {
      // This is an out-of process compilation; cache the pointer to the newly created well-known
      // class chain offsets in the client session to avoid sending repeated requests to the client
      clientData->cacheWellKnownClassChainOffsets(
         includedClasses, _wellKnownClasses.size(), classChainOffsets + 1, _wellKnownClassChainOffsets,
         (aotCacheStore && !missingClassChainRecords) ? classChainRecords : NULL, _aotCacheWellKnownClassesRecord
      );
      }
#endif /* defined(J9VM_OPT_JITSERVER) */

   SVM_ASSERT_NONFATAL(
      _wellKnownClassChainOffsets != NULL,
      "Failed to store well-known classes' class chains");

#undef REQUIRED_WELL_KNOWN_CLASS_COUNT
   }

bool
TR::SymbolValidationManager::validateWellKnownClasses(const uintptr_t *wellKnownClassChainOffsets)
   {
   // We may have already run populateWellKnownClasses on this
   // SymbolValidationManager, if there was no delay before processing the
   // relocations, in which case the Compilation is reused.
   bool assignNewIDs = _wellKnownClassChainOffsets == NULL;
   int classCount = static_cast<int>(wellKnownClassChainOffsets[0]);
   for (int i = 1; i <= classCount; i++)
      {
      uintptr_t classChainOffset = wellKnownClassChainOffsets[i];
      uintptr_t *classChain = reinterpret_cast<uintptr_t*>(
         _fej9->sharedCache()->pointerFromOffsetInSharedCache(classChainOffset));
      J9ROMClass *romClass = _fej9->sharedCache()->startingROMClassOfClassChain(classChain);
      J9UTF8 * className = J9ROMCLASS_CLASSNAME(romClass);

      TR_OpaqueClassBlock *clazz = _fej9->getSystemClassFromClassName(
         reinterpret_cast<const char *>(J9UTF8_DATA(className)),
         J9UTF8_LENGTH(className));

      if (clazz == NULL)
         return false;

      if (!_fej9->sharedCache()->classMatchesCachedVersion(clazz, classChain))
         return false;

      _seenValuesSet.insert(clazz);
      if (assignNewIDs)
         {
         _wellKnownClasses.push_back(clazz);
         if (clazz != _rootClass)
            setValueOfSymbolID(getNewSymbolID(), clazz, TR::SymbolType::typeClass);
         }
      }

   // These classes are definitely visible to any other class defined by the
   // bootstrap loader.
   _loadersOkForWellKnownClasses.push_back(TR::Compiler->javaVM->systemClassLoader);

   // The root class has a guaranteed ID, so it won't be newly encountered
   // later. Check now that its loader doesn't hide well-known classes.
   return classCanSeeWellKnownClasses(_rootClass);
   }

bool
TR::SymbolValidationManager::isWellKnownClass(TR_OpaqueClassBlock *clazz)
   {
   auto end = _wellKnownClasses.end();
   return std::find(_wellKnownClasses.begin(), end, clazz) != end;
   }

bool
TR::SymbolValidationManager::classCanSeeWellKnownClasses(TR_OpaqueClassBlock *beholder)
   {
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(reinterpret_cast<J9Class*>(beholder));
   if (beholderCP == NULL)
      {
      // This is a class with no CP, e.g. an array. (Are there any others?)
      // It can't be used for ClassFromSignature or ClassFromCP anyway.
      return true;
      }

   // Avoid repeated lookups using the same loader.
   J9ClassLoader *loader =
      reinterpret_cast<J9ClassLoader*>(_fej9->getClassLoader(beholder));
      {
      // Use linear search - the number of loaders will generally be small.
      auto begin = _loadersOkForWellKnownClasses.end();
      auto end = _loadersOkForWellKnownClasses.end();
      if (std::find(begin, end, loader) != end)
         return true;
      }

   // Check that every well-known class can be found. It's good enough here to
   // find anything (non-null) for a given name, because these names can only
   // be defined by the bootstrap loader, so if the class is found, then it
   // must be the same one found during validateWellKnownClasses().
   for (auto it = _wellKnownClasses.begin(); it != _wellKnownClasses.end(); ++it)
      {
      TR_OpaqueClassBlock *wkClass = *it;
      J9Class *wkJ9Class = reinterpret_cast<J9Class*>(wkClass);
      J9UTF8 *utf8 = J9ROMCLASS_CLASSNAME(wkJ9Class->romClass);
      char *name = reinterpret_cast<char *>(J9UTF8_DATA(utf8));
      uint32_t len = J9UTF8_LENGTH(utf8);
      if (_fej9->getClassFromSignature(name, len, beholderCP) == NULL)
         return false;
      }

   // All of the well-known classes are visible. This will be the case for all
   // classes using the same loader, because the well-known classes are public.
   _loadersOkForWellKnownClasses.push_back(loader);
   return true;
   }

bool
TR::SymbolValidationManager::isDefinedID(uint16_t id)
   {
   return id < _symbolToValueTable.size() && _symbolToValueTable[id]._hasValue;
   }

void
TR::SymbolValidationManager::setValueOfSymbolID(uint16_t id, void *value, TR::SymbolType type)
   {
   if (id >= _symbolToValueTable.size())
      {
      TypedValue unused = { NULL, typeOpaque, false };
      _symbolToValueTable.resize(id + 1, unused);
      }

   SVM_ASSERT(!_symbolToValueTable[id]._hasValue, "multiple definitions of ID %d", id);
   _symbolToValueTable[id]._value = value;
   _symbolToValueTable[id]._type = type;
   _symbolToValueTable[id]._hasValue = true;
   }

uint16_t
TR::SymbolValidationManager::getNewSymbolID()
   {
   SVM_ASSERT_NONFATAL(_symbolID != 0xFFFF, "symbol ID overflow");
   return _symbolID++;
   }

void *
TR::SymbolValidationManager::getValueFromSymbolID(uint16_t id, TR::SymbolType type, Presence presence)
   {
   TypedValue *entry = NULL;
   if (id < _symbolToValueTable.size())
      entry = &_symbolToValueTable[id];

   SVM_ASSERT(entry != NULL && entry->_hasValue, "Unknown ID %d", id);
   if (entry->_value == NULL)
      SVM_ASSERT(presence != SymRequired, "ID must not map to null");
   else
      SVM_ASSERT(entry->_type == type, "ID has type %d when %d was expected", entry->_type, type);

   return entry->_value;
   }

TR_OpaqueClassBlock *
TR::SymbolValidationManager::getClassFromID(uint16_t id, Presence presence)
   {
   return static_cast<TR_OpaqueClassBlock*>(
      getValueFromSymbolID(id, TR::SymbolType::typeClass, presence));
   }

J9Class *
TR::SymbolValidationManager::getJ9ClassFromID(uint16_t id, Presence presence)
   {
   return static_cast<J9Class*>(
      getValueFromSymbolID(id, TR::SymbolType::typeClass, presence));
   }

TR_OpaqueMethodBlock *
TR::SymbolValidationManager::getMethodFromID(uint16_t id, Presence presence)
   {
   return static_cast<TR_OpaqueMethodBlock*>(
      getValueFromSymbolID(id, TR::SymbolType::typeMethod, presence));
   }

J9Method *
TR::SymbolValidationManager::getJ9MethodFromID(uint16_t id, Presence presence)
   {
   return static_cast<J9Method*>(
      getValueFromSymbolID(id, TR::SymbolType::typeMethod, presence));
   }

uint16_t
TR::SymbolValidationManager::tryGetSymbolIDFromValue(void *value)
   {
   ValueToSymbolMap::iterator it = _valueToSymbolMap.find(value);
   if (it == _valueToSymbolMap.end())
      return NO_ID;
   else
      return it->second;
   }

uint16_t
TR::SymbolValidationManager::getSymbolIDFromValue(void *value)
   {
   uint16_t id = tryGetSymbolIDFromValue(value);
   SVM_ASSERT(id != NO_ID, "Unknown value %p\n", value);
   return id;
   }

TR_OpaqueClassBlock *
TR::SymbolValidationManager::getBaseComponentClass(TR_OpaqueClassBlock *clazz, int32_t &numDims)
   {
   numDims = 0;
   if (!clazz)
      return NULL;

   while (_fej9->isClassArray(clazz))
      {
      TR_OpaqueClassBlock * componentClass = _fej9->getComponentClassFromArrayClass(clazz);
      numDims++;
      clazz = componentClass;
      }

   return clazz;
   }

bool
TR::SymbolValidationManager::abandonRecord(TR::SymbolValidationRecord *record)
   {
   _region.deallocate(record);
   return inHeuristicRegion();
   }

bool
TR::SymbolValidationManager::recordExists(TR::SymbolValidationRecord *record)
   {
   return _alreadyGeneratedRecords.find(record) != _alreadyGeneratedRecords.end();
   }

bool
TR::SymbolValidationManager::anyClassFromCPRecordExists(
   TR_OpaqueClassBlock *clazz,
   TR_OpaqueClassBlock *beholder)
   {
   ClassFromAnyCPIndex pair(clazz, beholder);
   return _classesFromAnyCPIndex.find(pair) != _classesFromAnyCPIndex.end();
   }

void
TR::SymbolValidationManager::appendNewRecord(void *value, TR::SymbolValidationRecord *record)
   {
   SVM_ASSERT(!inHeuristicRegion(), "Attempted to appendNewRecord in a heuristic region");
   TR_ASSERT(!recordExists(record), "record is not new");

   if (!isAlreadyValidated(value))
      {
      _valueToSymbolMap.insert(std::make_pair(value, getNewSymbolID()));
      }
   _symbolValidationRecords.push_front(record);
   _alreadyGeneratedRecords.insert(record);

   record->printFields();
   traceMsg(_comp, "\tkind=%d\n", record->_kind);
   traceMsg(_comp, "\tid=%d\n", (uint32_t)getSymbolIDFromValue(value));
   traceMsg(_comp, "\n");
   }

void
TR::SymbolValidationManager::appendRecordIfNew(void *value, TR::SymbolValidationRecord *record)
   {
   if (recordExists(record))
      _region.deallocate(record);
   else
      appendNewRecord(value, record);
   }

bool
TR::SymbolValidationManager::getClassChainInfo(
   TR_OpaqueClassBlock *clazz,
   TR::SymbolValidationRecord *record,
   ClassChainInfo &info)
   {
   if (isAlreadyValidated(clazz))
      return true;

   // clazz is fresh, so a class chain validation may be necessary
   info._baseComponent = getBaseComponentClass(clazz, info._arrayDims);
   if (info._arrayDims == 0 || !isAlreadyValidated(info._baseComponent))
      {
      // info._baseComponent is a non-array reference type. It can't be a
      // primitive because primitives always satisfy isAlreadyValidated().
      const AOTCacheClassChainRecord *classChainRecord = NULL;
      info._baseComponentClassChainOffset = _fej9->sharedCache()->rememberClass(info._baseComponent, &classChainRecord);
      if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET == info._baseComponentClassChainOffset)
         {
         _region.deallocate(record);
         return false;
         }
#if defined(J9VM_OPT_JITSERVER)
      info._baseComponentAOTCacheClassChainRecord = classChainRecord;
#endif /* defined(J9VM_OPT_JITSERVER) */
      }

   return true;
   }

void
TR::SymbolValidationManager::appendClassChainInfoRecords(
   TR_OpaqueClassBlock *clazz,
   const ClassChainInfo &info)
   {
   // If clazz is a fresh array class, relate it to each component type.
   // Note that if clazz is not fresh, arrayDims is 0, which is fine because
   // this part has already been done for an earlier record.
   for (int i = 0; i < info._arrayDims; i++)
      {
      TR_OpaqueClassBlock *component = _fej9->getComponentClassFromArrayClass(clazz);
      appendRecordIfNew(
         component,
         new (_region) ArrayClassFromComponentClassRecord(clazz, component));
      clazz = component;
      }

   // If necessary, remember to validate the class chain of the base component type
   if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET != info._baseComponentClassChainOffset)
      {
      appendNewRecord(
         info._baseComponent,
         new (_region) ClassChainRecord(
            info._baseComponent,
            info._baseComponentClassChainOffset
#if defined(J9VM_OPT_JITSERVER)
            , info._baseComponentAOTCacheClassChainRecord
#endif /* defined(J9VM_OPT_JITSERVER) */
         ));
      }
   }

bool
TR::SymbolValidationManager::addVanillaRecord(void *value, TR::SymbolValidationRecord *record)
   {
   if (shouldNotDefineSymbol(value))
      return abandonRecord(record);

   appendRecordIfNew(value, record);
   return true;
   }

bool
TR::SymbolValidationManager::addClassRecord(TR_OpaqueClassBlock *clazz, TR::ClassValidationRecord *record)
   {
   if (shouldNotDefineSymbol(clazz) || !isClassWorthRemembering(clazz))
      return abandonRecord(record);

   if (recordExists(record))
      {
      _region.deallocate(record);
      return true;
      }

   ClassChainInfo chainInfo;
   if (!getClassChainInfo(clazz, record, chainInfo))
      return false;

   appendNewRecord(clazz, record); // The class is defined by the original record
   appendClassChainInfoRecords(clazz, chainInfo);
   return true;
   }

bool
TR::SymbolValidationManager::addClassRecordWithChain(TR::ClassValidationRecordWithChain *record)
   {
   if (shouldNotDefineSymbol(record->_class) || !isClassWorthRemembering(record->_class))
      return abandonRecord(record);

   int arrayDims = 0;
   record->_class = getBaseComponentClass(record->_class, arrayDims);

   if (!_fej9->isPrimitiveClass(record->_class))
      {
      const AOTCacheClassChainRecord *classChainRecord = NULL;
      record->_classChainOffset = _fej9->sharedCache()->rememberClass(record->_class, &classChainRecord);
      if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET == record->_classChainOffset)
         {
         _region.deallocate(record);
         return false;
         }

#if defined(J9VM_OPT_JITSERVER)
      record->_aotCacheClassChainRecord = classChainRecord;
#endif /* defined(J9VM_OPT_JITSERVER) */
      appendRecordIfNew(record->_class, record);
      }

   addMultipleArrayRecords(record->_class, arrayDims);
   return true;
   }

void
TR::SymbolValidationManager::addMultipleArrayRecords(TR_OpaqueClassBlock *component, int arrayDims)
   {
   for (int i = 0; i < arrayDims; i++)
      {
      TR_OpaqueClassBlock *array = _fej9->getArrayClassFromComponentClass(component);
      appendRecordIfNew(
         array,
         new (_region) ArrayClassFromComponentClassRecord(array, component));
      component = array;
      }
   }

bool
TR::SymbolValidationManager::addMethodRecord(TR::MethodValidationRecord *record)
   {
   if (shouldNotDefineSymbol(record->_method)
       || !isClassWorthRemembering(_fej9->getClassOfMethod(record->_method)))
      {
      return abandonRecord(record);
      }

   if (recordExists(record))
      {
      _region.deallocate(record);
      return true;
      }

   ClassChainInfo chainInfo;
   if (!getClassChainInfo(record->definingClass(_fej9), record, chainInfo))
      return false;

   appendNewRecord(record->_method, record);
   appendClassChainInfoRecords(record->definingClass(), chainInfo);
   return true;
   }

bool
TR::SymbolValidationManager::skipFieldRefClassRecord(
   TR_OpaqueClassBlock *definingClass,
   TR_OpaqueClassBlock *beholder,
   uint32_t cpIndex)
   {
   // If the beholder refers to one of its own fields, or to a field of a
   // well-known class, and if it does so by naming the class that declares the
   // field (not a subclass), then no record is necessary.
   if (definingClass == beholder || isWellKnownClass(definingClass))
      {
      int classRefLen;
      uint8_t *classRefName = TR::Compiler->cls.getROMClassRefName(_comp, beholder, cpIndex, classRefLen);
      J9UTF8 *definingClassNameUtf8 = J9ROMCLASS_CLASSNAME(TR::Compiler->cls.romClassOf(definingClass));
      int definingClassLen = J9UTF8_LENGTH(definingClassNameUtf8);
      uint8_t *definingClassName = J9UTF8_DATA(definingClassNameUtf8);

      if (classRefLen == definingClassLen
          && !memcmp(classRefName, definingClassName, classRefLen))
         {
         comp()->addAOTMethodDependency(definingClass);
         return true;
         }
      }

   return false;
   }

bool
TR::SymbolValidationManager::addClassByNameRecord(TR_OpaqueClassBlock *clazz, TR_OpaqueClassBlock *beholder)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   if (isWellKnownClass(clazz))
      {
      comp()->addAOTMethodDependency(clazz);
      return true;
      }
   else if (clazz == beholder)
      {
      return true;
      }
   else if (anyClassFromCPRecordExists(clazz, beholder))
      {
      return true; // already have an equivalent ClassFromCP
      }
   else
      {
      return addClassRecordWithChain(new (_region) ClassByNameRecord(clazz, beholder));
      }
   }

bool
TR::SymbolValidationManager::addProfiledClassRecord(TR_OpaqueClassBlock *clazz)
   {
   // check that clazz is non-null before trying to rememberClass
   if (shouldNotDefineSymbol(clazz))
      return inHeuristicRegion();

   int32_t arrayDims = 0;
   clazz = getBaseComponentClass(clazz, arrayDims);

   const AOTCacheClassChainRecord *classChainRecord = NULL;
   uintptr_t classChainOffset = _fej9->sharedCache()->rememberClass(clazz, &classChainRecord);
   if (TR_SharedCache::INVALID_CLASS_CHAIN_OFFSET == classChainOffset)
      return false;

   if (!isAlreadyValidated(clazz))
      appendNewRecord(clazz, new (_region) ProfiledClassRecord(clazz, classChainOffset, classChainRecord));

   addMultipleArrayRecords(clazz, arrayDims);
   return true;
   }

bool
TR::SymbolValidationManager::addClassFromCPRecord(TR_OpaqueClassBlock *clazz, J9ConstantPool *constantPoolOfBeholder, uint32_t cpIndex)
   {
   if (inHeuristicRegion())
      return true; // to make sure not to modify _classesFromAnyCPIndex

   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(constantPoolOfBeholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   if (isWellKnownClass(clazz))
      {
      comp()->addAOTMethodDependency(clazz);
      return true;
      }
   else if (clazz == beholder)
      {
      return true;
      }

   ClassByNameRecord byName(clazz, beholder);
   if (recordExists(&byName))
      return true; // already have an equivalent ClassByName

   bool added;
   if (!isAlreadyValidated(clazz)) // save a ClassChainRecord
      added = addClassRecordWithChain(new (_region) ClassByNameRecord(clazz, beholder));
   else
      added = addClassRecord(clazz, new (_region) ClassFromCPRecord(clazz, beholder, cpIndex));

   if (added)
      _classesFromAnyCPIndex.insert(ClassFromAnyCPIndex(clazz, beholder));

   return added;
   }

bool
TR::SymbolValidationManager::addDefiningClassFromCPRecord(TR_OpaqueClassBlock *clazz, J9ConstantPool *constantPoolOfBeholder, uint32_t cpIndex, bool isStatic)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(constantPoolOfBeholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   if (skipFieldRefClassRecord(clazz, beholder, cpIndex))
      return true;
   else
      return addClassRecord(clazz, new (_region) DefiningClassFromCPRecord(clazz, beholder, cpIndex, isStatic));
   }

bool
TR::SymbolValidationManager::addStaticClassFromCPRecord(TR_OpaqueClassBlock *clazz, J9ConstantPool *constantPoolOfBeholder, uint32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(constantPoolOfBeholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   if (skipFieldRefClassRecord(clazz, beholder, cpIndex))
       return true;
    else
      return addClassRecord(clazz, new (_region) StaticClassFromCPRecord(clazz, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addArrayClassFromComponentClassRecord(TR_OpaqueClassBlock *arrayClass, TR_OpaqueClassBlock *componentClass)
   {
   // Class chain validation for the base component type is already taken care of
   SVM_ASSERT_ALREADY_VALIDATED(this, componentClass);
   return addVanillaRecord(arrayClass, new (_region) ArrayClassFromComponentClassRecord(arrayClass, componentClass));
   }

bool
TR::SymbolValidationManager::addSuperClassFromClassRecord(TR_OpaqueClassBlock *superClass, TR_OpaqueClassBlock *childClass)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, childClass);
   return addClassRecord(superClass, new (_region) SuperClassFromClassRecord(superClass, childClass));
   }

bool
TR::SymbolValidationManager::addClassInstanceOfClassRecord(TR_OpaqueClassBlock *classOne, TR_OpaqueClassBlock *classTwo, bool objectTypeIsFixed, bool castTypeIsFixed, bool isInstanceOf)
   {
   // Not using addClassRecord() because this doesn't define a class symbol. We
   // can pass either class as the symbol because neither will get a fresh ID
   SVM_ASSERT_ALREADY_VALIDATED(this, classOne);
   SVM_ASSERT_ALREADY_VALIDATED(this, classTwo);

   // Skip creating a record when the subtyping relationship between the two
   // classes is known in advance.
   if (classOne == classTwo // classOne <: classTwo
      || _fej9->isJavaLangObject(classTwo) // classOne <: classTwo
      || _fej9->isJavaLangObject(classOne)) // !(classOne <: classTwo)
      return true;

   // Not using addClassRecord() because this doesn't define a class symbol. We
   // can pass either class as the symbol because neither will get a fresh ID
   return addVanillaRecord(classOne, new (_region) ClassInstanceOfClassRecord(classOne, classTwo, objectTypeIsFixed, castTypeIsFixed, isInstanceOf));
   }

bool
TR::SymbolValidationManager::addSystemClassByNameRecord(TR_OpaqueClassBlock *systemClass)
   {
   if (isWellKnownClass(systemClass))
      {
      comp()->addAOTMethodDependency(systemClass);
      return true;
      }
   else
      {
      return addClassRecordWithChain(new (_region) SystemClassByNameRecord(systemClass));
      }
   }

bool
TR::SymbolValidationManager::addClassFromITableIndexCPRecord(TR_OpaqueClassBlock *clazz, J9ConstantPool *constantPoolOfBeholder, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(constantPoolOfBeholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addClassRecord(clazz, new (_region) ClassFromITableIndexCPRecord(clazz, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addDeclaringClassFromFieldOrStaticRecord(TR_OpaqueClassBlock *clazz, J9ConstantPool *constantPoolOfBeholder, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(constantPoolOfBeholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   if (skipFieldRefClassRecord(clazz, beholder, cpIndex))
      return true;
   else
      return addClassRecord(clazz, new (_region) DeclaringClassFromFieldOrStaticRecord(clazz, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addConcreteSubClassFromClassRecord(TR_OpaqueClassBlock *childClass, TR_OpaqueClassBlock *superClass)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, superClass);
   return addClassRecord(childClass, new (_region) ConcreteSubClassFromClassRecord(childClass, superClass));
   }

bool
TR::SymbolValidationManager::addMethodFromClassRecord(TR_OpaqueMethodBlock *method, TR_OpaqueClassBlock *beholder, uint32_t index)
   {
   // In case index == -1, check that method is non-null up front, before searching.
   if (shouldNotDefineSymbol(method))
      return inHeuristicRegion();

   if (index == static_cast<uint32_t>(-1))
      {
      J9Method * resolvedMethods = static_cast<J9Method *>(_fej9->getMethods(beholder));
      uint32_t numMethods = _fej9->getNumMethods(beholder);
      for (index = 0; index < numMethods ; index++)
         {
         if ((TR_OpaqueMethodBlock *) &(resolvedMethods[index]) == method)
            break;
         }

      SVM_ASSERT(
         index < numMethods,
         "Method %p not found in class %p",
         method,
         beholder);
      }

   // Not using addMethodRecord() because this record itself relates the method
   // to its defining class, and the class chain has already been stored.
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addVanillaRecord(method, new (_region) MethodFromClassRecord(method, beholder, index));
   }

bool
TR::SymbolValidationManager::addStaticMethodFromCPRecord(TR_OpaqueMethodBlock *method, J9ConstantPool *cp, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(cp);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addMethodRecord(new (_region) StaticMethodFromCPRecord(method, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addSpecialMethodFromCPRecord(TR_OpaqueMethodBlock *method, J9ConstantPool *cp, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(cp);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addMethodRecord(new (_region) SpecialMethodFromCPRecord(method, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addVirtualMethodFromCPRecord(TR_OpaqueMethodBlock *method, J9ConstantPool *cp, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(cp);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addMethodRecord(new (_region) VirtualMethodFromCPRecord(method, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addVirtualMethodFromOffsetRecord(TR_OpaqueMethodBlock *method, TR_OpaqueClassBlock *beholder, int32_t virtualCallOffset, bool ignoreRtResolve)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);

   // Only need one bit, but it really should be a multiple of the pointer size
   SVM_ASSERT((virtualCallOffset & 1) == 0, "virtualCallOffset must be even");

   if (virtualCallOffset != (int32_t)(int16_t)virtualCallOffset)
      return false; // not enough space in the record

   return addMethodRecord(new (_region) VirtualMethodFromOffsetRecord(method, beholder, virtualCallOffset, ignoreRtResolve));
   }

bool
TR::SymbolValidationManager::addInterfaceMethodFromCPRecord(TR_OpaqueMethodBlock *method, TR_OpaqueClassBlock *beholder, TR_OpaqueClassBlock *lookup, int32_t cpIndex)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   SVM_ASSERT_ALREADY_VALIDATED(this, lookup);
   return addMethodRecord(new (_region) InterfaceMethodFromCPRecord(method, beholder, lookup, cpIndex));
   }

bool
TR::SymbolValidationManager::addImproperInterfaceMethodFromCPRecord(TR_OpaqueMethodBlock *method, J9ConstantPool *cp, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *beholder = _fej9->getClassFromCP(cp);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addMethodRecord(new (_region) ImproperInterfaceMethodFromCPRecord(method, beholder, cpIndex));
   }

bool
TR::SymbolValidationManager::addMethodFromClassAndSignatureRecord(TR_OpaqueMethodBlock *method, TR_OpaqueClassBlock *lookupClass, TR_OpaqueClassBlock *beholder)
   {
   // Check that method is non-null up front, since we need its class.
   if (shouldNotDefineSymbol(method))
      return inHeuristicRegion();

   SVM_ASSERT_ALREADY_VALIDATED(this, lookupClass);
   SVM_ASSERT_ALREADY_VALIDATED(this, beholder);
   return addMethodRecord(new (_region) MethodFromClassAndSigRecord(method, lookupClass, beholder));
   }

bool
TR::SymbolValidationManager::addMethodFromSingleImplementerRecord(TR_OpaqueMethodBlock *method,
                                                                  TR_OpaqueClassBlock *thisClass,
                                                                  int32_t cpIndexOrVftSlot,
                                                                  TR_OpaqueMethodBlock *callerMethod,
                                                                  TR_YesNoMaybe useGetResolvedInterfaceMethod)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, thisClass);
   SVM_ASSERT_ALREADY_VALIDATED(this, callerMethod);
   return addMethodRecord(new (_region) MethodFromSingleImplementer(method, thisClass, cpIndexOrVftSlot, callerMethod, useGetResolvedInterfaceMethod));
   }

bool
TR::SymbolValidationManager::addMethodFromSingleInterfaceImplementerRecord(TR_OpaqueMethodBlock *method,
                                                                           TR_OpaqueClassBlock *thisClass,
                                                                           int32_t cpIndex,
                                                                           TR_OpaqueMethodBlock *callerMethod)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, thisClass);
   SVM_ASSERT_ALREADY_VALIDATED(this, callerMethod);
   return addMethodRecord(new (_region) MethodFromSingleInterfaceImplementer(method, thisClass, cpIndex, callerMethod));
   }

bool
TR::SymbolValidationManager::addMethodFromSingleAbstractImplementerRecord(TR_OpaqueMethodBlock *method,
                                                                          TR_OpaqueClassBlock *thisClass,
                                                                          int32_t vftSlot,
                                                                          TR_OpaqueMethodBlock *callerMethod)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, thisClass);
   SVM_ASSERT_ALREADY_VALIDATED(this, callerMethod);
   return addMethodRecord(new (_region) MethodFromSingleAbstractImplementer(method, thisClass, vftSlot, callerMethod));
   }

bool
TR::SymbolValidationManager::addDynamicMethodFromCallsiteIndex(TR_OpaqueMethodBlock *method,
                                                               TR_OpaqueMethodBlock *caller,
                                                               int32_t callsiteIndex,
                                                               bool appendixObjectNull)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, caller);
   return addMethodRecord(new (_region) DynamicMethodFromCallsiteIndexRecord(method, caller, callsiteIndex, appendixObjectNull));
   }

bool
TR::SymbolValidationManager::addHandleMethodFromCPIndex(TR_OpaqueMethodBlock *method,
                                                        TR_OpaqueMethodBlock *caller,
                                                        int32_t cpIndex,
                                                        bool appendixObjectNull)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, caller);
   return addMethodRecord(new (_region) HandleMethodFromCPIndex(method, caller, cpIndex, appendixObjectNull));
   }

bool
TR::SymbolValidationManager::addStackWalkerMaySkipFramesRecord(TR_OpaqueMethodBlock *method, TR_OpaqueClassBlock *methodClass, bool skipFrames)
   {
   if (!method || !methodClass)
      return false;

   SVM_ASSERT_ALREADY_VALIDATED(this, method);
   SVM_ASSERT_ALREADY_VALIDATED(this, methodClass);
   return addVanillaRecord(method, new (_region) StackWalkerMaySkipFramesRecord(method, methodClass, skipFrames));
   }

bool
TR::SymbolValidationManager::addClassInfoIsInitializedRecord(TR_OpaqueClassBlock *clazz, bool isInitialized)
   {
   if (!isClassWorthRemembering(clazz))
      return false;

   SVM_ASSERT_ALREADY_VALIDATED(this, clazz);
   return addVanillaRecord(clazz, new (_region) ClassInfoIsInitialized(clazz, isInitialized));
   }

// This method doesn't return success/failure because it must succeed.
// Otherwise, it's not necessarily possible to codegen a resolved virtual call,
// since the call might not have originated as a regular invokevirtual.
void
TR::SymbolValidationManager::addJ2IThunkFromMethodRecord(void *thunk, TR_OpaqueMethodBlock *method)
   {
   SVM_ASSERT(thunk != NULL, "addJ2IThunkFromMethodRecord: no thunk");
   SVM_ASSERT_ALREADY_VALIDATED(this, method);
   if (isAlreadyValidated(thunk))
      {
      // We've already seen this thunk defined by an earlier J2IThunkFromMethod
      // record given some previous method M. Call the `method` currently under
      // consideration N. Then the signatures of M and N are compatible for the
      // purposes of J2I thunk sharing.
      //
      // If we reach this point in the validation at load time, there are
      // corresponding methods M' and N' with signatures identical to those of
      // M and N, respectively. In particular, M' and N' will share a single
      // J2I thunk. Furthermore, that J2I thunk is already guaranteed to exist
      // because it has been ensured for M' by the earlier J2IThunkFromMethod
      // record. Therefore, there is no need for a second record.
      //
      // Well either that or we're in a heuristic region, but in that case we
      // should still return without creating any new records.
      //
      return;
      }

   TR::SymbolValidationRecord *record =
      new (_region) J2IThunkFromMethodRecord(thunk, method);

   SVM_ASSERT(
      !recordExists(record),
      "J2IThunkFromMethod record (thunk %p, method %p) already exists, "
      "but the thunk has not been assigned an ID",
      thunk,
      method);

   appendNewRecord(thunk, record);
   }

bool
TR::SymbolValidationManager::addIsClassVisibleRecord(TR_OpaqueClassBlock *sourceClass, TR_OpaqueClassBlock *destClass, bool isVisible)
   {
   SVM_ASSERT_ALREADY_VALIDATED(this, sourceClass);
   SVM_ASSERT_ALREADY_VALIDATED(this, destClass);

   // Skip creating a record when destClass is a Java.lang.Object
   // because Object is always visible
   if (sourceClass == destClass
      || _fej9->isJavaLangObject(destClass))
      return true;

   return addVanillaRecord(sourceClass, new (_region) IsClassVisibleRecord(sourceClass, destClass, isVisible));
   }



bool
TR::SymbolValidationManager::validateSymbol(uint16_t idToBeValidated, void *validValue, TR::SymbolType type)
   {
   bool valid = false;
   TypedValue *entry = NULL;
   if (idToBeValidated < _symbolToValueTable.size())
      entry = &_symbolToValueTable[idToBeValidated];

   if (entry == NULL || !entry->_hasValue)
      {
      if (_seenValuesSet.find(validValue) == _seenValuesSet.end())
         {
         valid = true;
         if (type == TR::SymbolType::typeClass)
            {
            valid = classCanSeeWellKnownClasses(
               reinterpret_cast<TR_OpaqueClassBlock*>(validValue));
            }

         if (valid)
            {
            setValueOfSymbolID(idToBeValidated, validValue, type);
            _seenValuesSet.insert(validValue);
            }
         }
      }
   else
      {
      valid = validValue == entry->_value
         && (validValue == NULL || entry->_type == type);
      }

   return valid;
   }

bool
TR::SymbolValidationManager::validateSymbol(uint16_t idToBeValidated, TR_OpaqueClassBlock *clazz)
   {
   return validateSymbol(idToBeValidated, clazz, TR::SymbolType::typeClass);
   }

bool
TR::SymbolValidationManager::validateSymbol(uint16_t idToBeValidated, J9Class *clazz)
   {
   return validateSymbol(idToBeValidated, clazz, TR::SymbolType::typeClass);
   }

bool
TR::SymbolValidationManager::validateSymbol(uint16_t methodID, uint16_t definingClassID, TR_OpaqueMethodBlock *method)
   {
   return validateSymbol(methodID, definingClassID, reinterpret_cast<J9Method*>(method));
   }

bool
TR::SymbolValidationManager::validateSymbol(uint16_t methodID, uint16_t definingClassID, J9Method *method)
   {
   J9Class *definingClass = method == NULL ? NULL : J9_CLASS_FROM_METHOD(method);
   return validateSymbol(methodID, method, TR::SymbolType::typeMethod)
      && validateSymbol(definingClassID, definingClass);
   }

bool
TR::SymbolValidationManager::validateClassByNameRecord(uint16_t classID, uint16_t beholderID, uintptr_t *classChain)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   J9ROMClass *romClass = _fej9->sharedCache()->startingROMClassOfClassChain(classChain);
   J9UTF8 * classNameData = J9ROMCLASS_CLASSNAME(romClass);
   char *className = reinterpret_cast<char *>(J9UTF8_DATA(classNameData));
   uint32_t classNameLength = J9UTF8_LENGTH(classNameData);
   TR_OpaqueClassBlock *clazz = _fej9->getClassFromSignature(className, classNameLength, beholderCP);
   return validateSymbol(classID, clazz)
      && _fej9->sharedCache()->classMatchesCachedVersion(clazz, classChain);
   }

bool
TR::SymbolValidationManager::validateProfiledClassRecord(uint16_t classID, void *classChainIdentifyingLoader,
                                                         void *classChainForClassBeingValidated)
   {

   static bool bypassProfiledRecord = feGetEnv("TR_DepTableNoBypassProfiledRecord") == NULL;
   auto dependencyTable = _fej9->getPersistentInfo()->getAOTDependencyTable();
   if (bypassProfiledRecord && dependencyTable)
      {
      if (isDefinedID(classID))
         {
         auto svmCandidate = getJ9ClassFromID(classID, SymOptional);
         return svmCandidate ? dependencyTable->classMatchesCachedVersion((TR_OpaqueClassBlock *)svmCandidate, (uintptr_t *)classChainForClassBeingValidated) : false;
         }
      else
         {
         auto dependencyCandidate = dependencyTable->findCandidateWithChainAndLoader(_comp, (uintptr_t *)classChainForClassBeingValidated, classChainIdentifyingLoader);
         return validateSymbol(classID, dependencyCandidate);
         }
      }

   J9ClassLoader *classLoader = (J9ClassLoader *)_fej9->sharedCache()->lookupClassLoaderAssociatedWithClassChain(classChainIdentifyingLoader);
   if (classLoader == NULL)
      return false;

   TR_OpaqueClassBlock *clazz = _fej9->sharedCache()->lookupClassFromChainAndLoader(
      static_cast<uintptr_t *>(classChainForClassBeingValidated), classLoader, _comp
   );
   return validateSymbol(classID, clazz);
   }

bool
TR::SymbolValidationManager::validateClassFromCPRecord(uint16_t classID,  uint16_t beholderID, uint32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   return validateSymbol(classID, TR_ResolvedJ9Method::getClassFromCP(_fej9, beholderCP, _comp, cpIndex));
   }

bool
TR::SymbolValidationManager::validateDefiningClassFromCPRecord(uint16_t classID, uint16_t beholderID, uint32_t cpIndex, bool isStatic)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   return validateSymbol(classID, TR_ResolvedJ9Method::definingClassFromCPFieldRef(_comp, beholderCP, cpIndex, isStatic));
   }

bool
TR::SymbolValidationManager::validateStaticClassFromCPRecord(uint16_t classID, uint16_t beholderID, uint32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);

   if (cpIndex != -1)
      {
      TR::VMAccessCriticalSection getClassFromConstantPool(_fej9);
      _fej9->_vmFunctionTable->resolveStaticFieldRef(_fej9->vmThread(), NULL, beholderCP, cpIndex, J9_RESOLVE_FLAG_JIT_COMPILE_TIME, NULL);
      }

   return validateSymbol(classID, TR_ResolvedJ9Method::getClassOfStaticFromCP(_fej9, beholderCP, cpIndex));
   }

bool
TR::SymbolValidationManager::validateArrayClassFromComponentClassRecord(uint16_t arrayClassID, uint16_t componentClassID)
   {
   if (isDefinedID(componentClassID))
      {
      TR_OpaqueClassBlock *componentClass = getClassFromID(componentClassID);
      if (validateSymbol(arrayClassID, _fej9->getArrayClassFromComponentClass(componentClass)))
         return true;

      TR_OpaqueClassBlock *nullRestrictedArray = _fej9->getNullRestrictedArrayClassFromComponentClass(componentClass);
      return nullRestrictedArray ? validateSymbol(arrayClassID, nullRestrictedArray) : false;
      }
   else
      {
      TR_OpaqueClassBlock *arrayClass = getClassFromID(arrayClassID);
      if (_fej9->isClassArray(arrayClass))
         return validateSymbol(componentClassID, _fej9->getComponentClassFromArrayClass(arrayClass));
      else
         return false;
      }
   }

bool
TR::SymbolValidationManager::validateSuperClassFromClassRecord(uint16_t superClassID, uint16_t childClassID)
   {
   TR_OpaqueClassBlock *childClass = getClassFromID(childClassID);
   return validateSymbol(superClassID, _fej9->getSuperClass(childClass));
   }

bool
TR::SymbolValidationManager::validateClassInstanceOfClassRecord(uint16_t classOneID, uint16_t classTwoID, bool objectTypeIsFixed, bool castTypeIsFixed, bool wasInstanceOf)
   {
   TR_OpaqueClassBlock *classOne = getClassFromID(classOneID);
   TR_OpaqueClassBlock *classTwo = getClassFromID(classTwoID);

   TR_YesNoMaybe isInstanceOf = _fej9->isInstanceOf(classOne, classTwo, objectTypeIsFixed, castTypeIsFixed);

   return (wasInstanceOf == (isInstanceOf == TR_yes));
   }

bool
TR::SymbolValidationManager::validateSystemClassByNameRecord(uint16_t systemClassID, uintptr_t *classChain)
   {
   J9ROMClass *romClass = _fej9->sharedCache()->startingROMClassOfClassChain(classChain);
   J9UTF8 * className = J9ROMCLASS_CLASSNAME(romClass);
   TR_OpaqueClassBlock *systemClassByName = _fej9->getSystemClassFromClassName(reinterpret_cast<const char *>(J9UTF8_DATA(className)),
                                                                              J9UTF8_LENGTH(className));
   return validateSymbol(systemClassID, systemClassByName)
      && _fej9->sharedCache()->classMatchesCachedVersion(systemClassByName, classChain);
   }

bool
TR::SymbolValidationManager::validateClassFromITableIndexCPRecord(uint16_t classID, uint16_t beholderID, uint32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   uintptr_t pITableIndex;
   return validateSymbol(classID, TR_ResolvedJ9Method::getInterfaceITableIndexFromCP(_fej9, beholderCP, cpIndex, &pITableIndex));
   }

bool
TR::SymbolValidationManager::validateDeclaringClassFromFieldOrStaticRecord(uint16_t definingClassID, uint16_t beholderID, int32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ROMClass *beholderRomClass = beholder->romClass;
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   J9ROMFieldRef *romCPBase = (J9ROMFieldRef *)((UDATA)beholderRomClass + sizeof(J9ROMClass));

   int32_t classCPIndexOfFieldOrStatic = -1;
   if (cpIndex != -1)
      classCPIndexOfFieldOrStatic = ((J9ROMFieldRef *)(&romCPBase[cpIndex]))->classRefCPIndex;

   J9Class *definingClass = NULL;
   J9Class *cpClass = (J9Class*)TR_ResolvedJ9Method::getClassFromCP(_fej9, beholderCP, _comp, classCPIndexOfFieldOrStatic);

   if (cpClass)
      {
      TR::VMAccessCriticalSection getDeclaringClassFromFieldOrStatic(_fej9);

      int32_t fieldLen = 0;
      char *field = cpIndex >= 0 ? utf8Data(J9ROMNAMEANDSIGNATURE_NAME(J9ROMFIELDREF_NAMEANDSIGNATURE(&romCPBase[cpIndex])), fieldLen) : 0;

      int32_t sigLen = 0;
      char *sig = cpIndex >= 0 ? utf8Data(J9ROMNAMEANDSIGNATURE_SIGNATURE(J9ROMFIELDREF_NAMEANDSIGNATURE(&romCPBase[cpIndex])), sigLen) : 0;

      _vmThread->javaVM->internalVMFunctions->instanceFieldOffset(
         _vmThread,
         cpClass,
         (U_8*)field,
         fieldLen,
         (U_8*)sig,
         sigLen,
         &definingClass,
         NULL,
         J9_LOOK_NO_JAVA);
      }
   else
      {
      return false;
      }

   return validateSymbol(definingClassID, definingClass);
   }

bool
TR::SymbolValidationManager::validateConcreteSubClassFromClassRecord(uint16_t childClassID, uint16_t superClassID)
   {
   TR_OpaqueClassBlock *superClass = getClassFromID(superClassID);
   TR_OpaqueClassBlock *childClass = _chTable->findSingleConcreteSubClass(superClass, _comp, false);
   return validateSymbol(childClassID, childClass);
   }

bool
TR::SymbolValidationManager::validateClassChainRecord(uint16_t classID, void *classChain)
   {
   TR_OpaqueClassBlock *definingClass = getClassFromID(classID);
   return _fej9->sharedCache()->classMatchesCachedVersion(definingClass, (uintptr_t *) classChain);
   }

bool
TR::SymbolValidationManager::validateMethodFromClassRecord(uint16_t methodID, uint16_t beholderID, uint32_t index)
   {
   TR_OpaqueClassBlock *beholder = getClassFromID(beholderID);
   J9Method *method;

      {
      TR::VMAccessCriticalSection getResolvedMethods(_fej9); // Prevent HCR
      J9Method *methods = static_cast<J9Method *>(_fej9->getMethods(beholder));
      uint32_t numMethods = _fej9->getNumMethods(beholder);
      SVM_ASSERT(index < numMethods, "Index is not within the bounds of the ramMethods array");
      method = &(methods[index]);
      }

   // The defining class is necessarily the same class we looked in
   return validateSymbol(methodID, beholderID, method);
   }

bool
TR::SymbolValidationManager::validateStaticMethodFromCPRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, int32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   J9Method *ramMethod;

      {
      TR::VMAccessCriticalSection getResolvedStaticMethod(_fej9);
      ramMethod = jitResolveStaticMethodRef(_vmThread, beholderCP, cpIndex, J9_RESOLVE_FLAG_JIT_COMPILE_TIME);
      }

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateSpecialMethodFromCPRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, int32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   J9Method *ramMethod;

      {
      TR::VMAccessCriticalSection resolveSpecialMethodRef(_fej9);
      ramMethod = jitResolveSpecialMethodRef(_vmThread, beholderCP, cpIndex, J9_RESOLVE_FLAG_JIT_COMPILE_TIME);
      }

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateVirtualMethodFromCPRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, int32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);

   UDATA vTableOffset;
   bool unresolvedInCP;
   TR_OpaqueMethodBlock * ramMethod = TR_ResolvedJ9Method::getVirtualMethod(_fej9, beholderCP, cpIndex, &vTableOffset, &unresolvedInCP);

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateVirtualMethodFromOffsetRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, int32_t virtualCallOffset, bool ignoreRtResolve)
   {
   TR_OpaqueClassBlock *beholder = getClassFromID(beholderID);

   TR_OpaqueMethodBlock *ramMethod = _fej9->getResolvedVirtualMethod(beholder, virtualCallOffset, ignoreRtResolve);

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateInterfaceMethodFromCPRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, uint16_t lookupID, int32_t cpIndex)
   {
   TR_OpaqueClassBlock *lookup = getClassFromID(lookupID);

   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);

   TR_OpaqueMethodBlock *ramMethod = _fej9->getResolvedInterfaceMethod(beholderCP, lookup, cpIndex);

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateImproperInterfaceMethodFromCPRecord(uint16_t methodID, uint16_t definingClassID, uint16_t beholderID, int32_t cpIndex)
   {
   J9Class *beholder = getJ9ClassFromID(beholderID);
   J9ConstantPool *beholderCP = J9_CP_FROM_CLASS(beholder);
   J9Method *ramMethod;

      {
      TR::VMAccessCriticalSection resolveImproperMethodRef(_fej9);
      ramMethod = jitGetImproperInterfaceMethodFromCP(_vmThread, beholderCP, cpIndex, NULL);
      }

   return validateSymbol(methodID, definingClassID, ramMethod);
   }

bool
TR::SymbolValidationManager::validateMethodFromClassAndSignatureRecord(uint16_t methodID, uint16_t definingClassID, uint16_t lookupClassID, uint16_t beholderID, J9ROMMethod *romMethod)
   {
   TR_OpaqueClassBlock *lookupClass = getClassFromID(lookupClassID);
   TR_OpaqueClassBlock *beholder = getClassFromID(beholderID, SymOptional);

   J9UTF8 *methodNameData = J9ROMMETHOD_NAME(romMethod);
   char *methodName = (char *)alloca(J9UTF8_LENGTH(methodNameData)+1);
   strncpy(methodName, reinterpret_cast<const char *>(J9UTF8_DATA(methodNameData)), J9UTF8_LENGTH(methodNameData));
   methodName[J9UTF8_LENGTH(methodNameData)] = '\0';

   J9UTF8 *methodSigData = J9ROMMETHOD_SIGNATURE(romMethod);
   char *methodSig = (char *)alloca(J9UTF8_LENGTH(methodSigData)+1);
   strncpy(methodSig, reinterpret_cast<const char *>(J9UTF8_DATA(methodSigData)), J9UTF8_LENGTH(methodSigData));
   methodSig[J9UTF8_LENGTH(methodSigData)] = '\0';

   TR_OpaqueMethodBlock *method = _fej9->getMethodFromClass(lookupClass, methodName, methodSig, beholder);

   return validateSymbol(methodID, definingClassID, method);
   }

bool
TR::SymbolValidationManager::validateMethodFromSingleImplementerRecord(uint16_t methodID,
                                                                       uint16_t definingClassID,
                                                                       uint16_t thisClassID,
                                                                       int32_t cpIndexOrVftSlot,
                                                                       uint16_t callerMethodID,
                                                                       TR_YesNoMaybe useGetResolvedInterfaceMethod)
   {
   TR_OpaqueClassBlock *thisClass = getClassFromID(thisClassID);
   TR_OpaqueMethodBlock *callerMethod = getMethodFromID(callerMethodID);

   TR_ResolvedMethod *callerResolvedMethod = _fej9->createResolvedMethod(_trMemory, callerMethod, NULL);
   TR_ResolvedMethod *calleeResolvedMethod = _chTable->findSingleImplementer(thisClass, cpIndexOrVftSlot, callerResolvedMethod, _comp, false, useGetResolvedInterfaceMethod, false);

   if (!calleeResolvedMethod)
      return false;

   TR_OpaqueMethodBlock *method = calleeResolvedMethod->getPersistentIdentifier();

   return validateSymbol(methodID, definingClassID, method);
   }

bool
TR::SymbolValidationManager::validateMethodFromSingleInterfaceImplementerRecord(uint16_t methodID,
                                                                                uint16_t definingClassID,
                                                                                uint16_t thisClassID,
                                                                                int32_t cpIndex,
                                                                                uint16_t callerMethodID)
   {
   TR_OpaqueClassBlock *thisClass = getClassFromID(thisClassID);
   TR_OpaqueMethodBlock *callerMethod = getMethodFromID(callerMethodID);

   TR_ResolvedMethod *callerResolvedMethod = _fej9->createResolvedMethod(_trMemory, callerMethod, NULL);
   TR_ResolvedMethod *calleeResolvedMethod = _chTable->findSingleInterfaceImplementer(thisClass, cpIndex, callerResolvedMethod, _comp, false, false);

   if (!calleeResolvedMethod)
      return false;

   TR_OpaqueMethodBlock *method = calleeResolvedMethod->getPersistentIdentifier();

   return validateSymbol(methodID, definingClassID, method);
   }

bool
TR::SymbolValidationManager::validateMethodFromSingleAbstractImplementerRecord(uint16_t methodID,
                                                                               uint16_t definingClassID,
                                                                               uint16_t thisClassID,
                                                                               int32_t vftSlot,
                                                                               uint16_t callerMethodID)
   {
   TR_OpaqueClassBlock *thisClass = getClassFromID(thisClassID);
   TR_OpaqueMethodBlock *callerMethod = getMethodFromID(callerMethodID);

   TR_ResolvedMethod *callerResolvedMethod = _fej9->createResolvedMethod(_trMemory, callerMethod, NULL);
   TR_ResolvedMethod *calleeResolvedMethod = _chTable->findSingleAbstractImplementer(thisClass, vftSlot, callerResolvedMethod, _comp, false, false);

   if (!calleeResolvedMethod)
      return false;

   TR_OpaqueMethodBlock *method = calleeResolvedMethod->getPersistentIdentifier();

   return validateSymbol(methodID, definingClassID, method);
   }

bool
TR::SymbolValidationManager::validateDynamicMethodFromCallsiteIndex(uint16_t methodID,
                                                                    uint16_t callerID,
                                                                    int32_t callsiteIndex,
                                                                    bool appendixObjectNull,
                                                                    uint16_t definingClassID,
                                                                    uint32_t methodIndex)
   {
   bool valid = false;

#if defined(J9VM_OPT_OPENJDK_METHODHANDLE)
   TR_OpaqueMethodBlock *caller = getMethodFromID(callerID);
   TR_ResolvedMethod *resolvedCaller = _fej9->createResolvedMethod(_trMemory, caller, NULL);

   // If dispatch was resolved at compile time, it must also be resolved
   // at load time.
   if (!resolvedCaller->isUnresolvedCallSiteTableEntry(callsiteIndex))
      {
      uintptr_t * invokeCacheArray = (uintptr_t *)resolvedCaller->callSiteTableEntryAddress(callsiteIndex);
      if (_fej9->isInvokeCacheEntryAnArray(invokeCacheArray))
         {
         bool invokeCacheAppendixNull = false;

         TR_OpaqueMethodBlock *targetMethod =
            static_cast<TR_ResolvedJ9Method *>(resolvedCaller)->getTargetMethodFromMemberName(
               invokeCacheArray, &invokeCacheAppendixNull);

         TR_OpaqueClassBlock *targetMethodClass =
            reinterpret_cast<TR_OpaqueClassBlock *>(
               J9_CLASS_FROM_METHOD(reinterpret_cast<J9Method *>(targetMethod)));

         valid =
            validateSymbol(methodID, definingClassID, targetMethod)

            // The generated code is different depending on whether the
            // appendix object was null or not.
            && (appendixObjectNull == invokeCacheAppendixNull)

            // Because the target method is not named, this (indirectly) ensures
            // that the target method has the same name as in the compile run;
            // the class chain validation of the defining class will ensure the
            // bytecodes are the same.
            && (methodIndex == _fej9->getMethodIndexInClass(targetMethodClass, targetMethod));
         }
      }
#endif /* defined(J9VM_OPT_OPENJDK_METHODHANDLE) */

   return valid;
   }

bool
TR::SymbolValidationManager::validateHandleMethodFromCPIndex(uint16_t methodID,
                                                             uint16_t callerID,
                                                             int32_t cpIndex,
                                                             bool appendixObjectNull,
                                                             uint16_t definingClassID,
                                                             uint32_t methodIndex)
   {
   bool valid = false;

#if defined(J9VM_OPT_OPENJDK_METHODHANDLE)
   TR_OpaqueMethodBlock *caller = getMethodFromID(callerID);
   TR_ResolvedMethod *resolvedCaller = _fej9->createResolvedMethod(_trMemory, caller, NULL);

   // If dispatch was resolved at compile time, it must also be resolved
   // at load time.
   if (!resolvedCaller->isUnresolvedMethodTypeTableEntry(cpIndex))
      {
      uintptr_t * invokeCacheArray = (uintptr_t *)resolvedCaller->methodTypeTableEntryAddress(cpIndex);
      bool invokeCacheAppendixNull = false;

      TR_OpaqueMethodBlock *targetMethod =
         static_cast<TR_ResolvedJ9Method *>(resolvedCaller)->getTargetMethodFromMemberName(
            invokeCacheArray, &invokeCacheAppendixNull);

      TR_OpaqueClassBlock *targetMethodClass =
         reinterpret_cast<TR_OpaqueClassBlock *>(
            J9_CLASS_FROM_METHOD(reinterpret_cast<J9Method *>(targetMethod)));

      valid =
         validateSymbol(methodID, definingClassID, targetMethod)

         // The generated code is different depending on whether the
         // appendix object was null or not.
         && (appendixObjectNull == invokeCacheAppendixNull)

         // Because the target method is not named, this (indirectly) ensures
         // that the target method has the same name as in the compile run;
         // the class chain validation of the defining class will ensure the
         // bytecodes are the same.
         && (methodIndex == _fej9->getMethodIndexInClass(targetMethodClass, targetMethod));
      }
#endif /* defined(J9VM_OPT_OPENJDK_METHODHANDLE) */

   return valid;
   }

bool
TR::SymbolValidationManager::validateStackWalkerMaySkipFramesRecord(uint16_t methodID, uint16_t methodClassID, bool couldSkipFrames)
   {
   TR_OpaqueMethodBlock *method = getMethodFromID(methodID);
   TR_OpaqueClassBlock *methodClass = getClassFromID(methodClassID);

   bool canSkipFrames = _fej9->stackWalkerMaySkipFrames(method, methodClass);

   return (canSkipFrames == couldSkipFrames);
   }

bool
TR::SymbolValidationManager::validateClassInfoIsInitializedRecord(uint16_t classID, bool wasInitialized)
   {
   TR_OpaqueClassBlock *clazz = getClassFromID(classID);

   bool initialized = false;

   TR_PersistentClassInfo * classInfo =
      _chTable->findClassInfoAfterLocking(clazz, _comp, true);

   if (classInfo)
      initialized = classInfo->isInitialized(false);

   bool valid = (!wasInitialized || initialized);
   return valid;
   }

bool
TR::SymbolValidationManager::validateJ2IThunkFromMethodRecord(uint16_t thunkID, void *thunk)
   {
   return validateSymbol(thunkID, thunk, TR::SymbolType::typeOpaque);
   }

bool
TR::SymbolValidationManager::validateIsClassVisibleRecord(uint16_t sourceClassID, uint16_t destClassID, bool wasVisible)
   {
   TR_OpaqueClassBlock *sourceClass = getClassFromID(sourceClassID);
   TR_OpaqueClassBlock *destClass = getClassFromID(destClassID);

   bool isVisible = _fej9->isClassVisible(sourceClass, destClass);

   return (isVisible == wasVisible);
   }

bool
TR::SymbolValidationManager::assertionsAreFatal()
   {
   // Look for the env var even in debug builds so that it's always acknowledged.
   static const bool fatal = feGetEnv("TR_svmAssertionsAreFatal") != NULL;

   if (fatal)
      return true;

#if defined(DEBUG) || defined(PROD_WITH_ASSUMES) || defined(SVM_ASSERTIONS_ARE_FATAL)
   TR::Compilation *comp = TR::comp();
   // TR_IgnoreAssert: ignore nonfatal assertion failures.
   return !comp || !comp->getOption(TR_IgnoreAssert);
#else
   return false;
#endif /* defined(DEBUG) || defined(PROD_WITH_ASSUMES) || defined(SVM_ASSERTIONS_ARE_FATAL) */
   }

static void printClass(TR_OpaqueClassBlock *clazz)
   {
   if (clazz != NULL)
      {
      J9UTF8 *className = J9ROMCLASS_CLASSNAME(TR::Compiler->cls.romClassOf(clazz));
      traceMsg(TR::comp(), "\tclassName=%.*s\n", J9UTF8_LENGTH(className), J9UTF8_DATA(className));
      }
   }

namespace // file-local
   {
   class LexicalOrder
      {
      enum Result
         {
         LESS,
         EQUAL,
         GREATER,
         };

      public:
      LexicalOrder() : _result(EQUAL) { }
      LexicalOrder(const LexicalOrder &other) : _result(other._result) { }

      static LexicalOrder by(void *a, void *b) { return LexicalOrder().thenBy(a, b); }
      static LexicalOrder by(uintptr_t a, uintptr_t b) { return LexicalOrder().thenBy(a, b); }

      LexicalOrder &thenBy(void *a, void *b)
         {
         if (_result == EQUAL)
            _result = a == b ? EQUAL : ::std::less<void*>()(a, b) ? LESS : GREATER;
         return *this;
         }

      LexicalOrder &thenBy(uintptr_t a, uintptr_t b)
         {
         if (_result == EQUAL)
            _result = a == b ? EQUAL : a < b ? LESS : GREATER;
         return *this;
         }

      bool less() const { return _result == LESS; }

      private:
      Result _result;
      };
   }

void TR::ClassValidationRecordWithChain::printFields()
   {
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_classChainOffset=%" OMR_PRIuPTR "\n", _classChainOffset);
   }

bool TR::ClassByNameRecord::isLessThanWithinKind(SymbolValidationRecord *other)
   {
   TR::ClassByNameRecord *rhs = downcast(this, other);
   // Don't compare _classChain - it's determined by _class
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder).less();
   }

void TR::ClassByNameRecord::printFields()
   {
   traceMsg(TR::comp(), "ClassByNameRecord\n");
   TR::ClassValidationRecordWithChain::printFields();
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   }

bool TR::ProfiledClassRecord::isLessThanWithinKind(SymbolValidationRecord *other)
   {
   TR::ProfiledClassRecord *rhs = downcast(this, other);
   // Don't compare _classChain - it's determined by _class
   return LexicalOrder::by(_class, rhs->_class).less();
   }

void TR::ProfiledClassRecord::printFields()
   {
   traceMsg(TR::comp(), "ProfiledClassRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_classChainOffset=%" OMR_PRIuPTR "\n", _classChainOffset);
   }

bool TR::ClassFromCPRecord::isLessThanWithinKind(SymbolValidationRecord *other)
   {
   TR::ClassFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::ClassFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "ClassFromCPRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::DefiningClassFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::DefiningClassFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex)
      .thenBy(_isStatic, rhs->_isStatic).less();
   }

void TR::DefiningClassFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "DefiningClassFromCPRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   traceMsg(TR::comp(), "\t_isStatic=%s\n", (_isStatic ? "true" : "false"));
   }

bool TR::StaticClassFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::StaticClassFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::StaticClassFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "StaticClassFromCPRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::ArrayClassFromComponentClassRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ArrayClassFromComponentClassRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_arrayClass, rhs->_arrayClass)
      .thenBy(_componentClass, rhs->_componentClass).less();
   }

void TR::ArrayClassFromComponentClassRecord::printFields()
   {
   traceMsg(TR::comp(), "ArrayClassFromComponentClassRecord\n");
   traceMsg(TR::comp(), "\t_arrayClass=0x%p\n", _arrayClass);
   printClass(_arrayClass);
   traceMsg(TR::comp(), "\t_componentClass=0x%p\n", _componentClass);
   printClass(_componentClass);
   }

bool TR::SuperClassFromClassRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::SuperClassFromClassRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_superClass, rhs->_superClass)
      .thenBy(_childClass, rhs->_childClass).less();
   }

void TR::SuperClassFromClassRecord::printFields()
   {
   traceMsg(TR::comp(), "SuperClassFromClassRecord\n");
   traceMsg(TR::comp(), "\t_superClass=0x%p\n", _superClass);
   printClass(_superClass);
   traceMsg(TR::comp(), "\t_childClass=0x%p\n", _childClass);
   printClass(_childClass);
   }

bool TR::ClassInstanceOfClassRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ClassInstanceOfClassRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_classOne, rhs->_classOne)
      .thenBy(_classTwo, rhs->_classTwo)
      .thenBy(_objectTypeIsFixed, rhs->_objectTypeIsFixed)
      .thenBy(_castTypeIsFixed, rhs->_castTypeIsFixed)
      .thenBy(_isInstanceOf, rhs->_isInstanceOf).less();
   }

void TR::ClassInstanceOfClassRecord::printFields()
   {
   traceMsg(TR::comp(), "ClassInstanceOfClassRecord\n");
   traceMsg(TR::comp(), "\t_classOne=0x%p\n", _classOne);
   printClass(_classOne);
   traceMsg(TR::comp(), "\t_classTwo=0x%p\n", _classTwo);
   printClass(_classTwo);
   traceMsg(TR::comp(), "\t_objectTypeIsFixed=%s\n", _objectTypeIsFixed ? "true" : "false");
   traceMsg(TR::comp(), "\t_castTypeIsFixed=%s\n", _castTypeIsFixed ? "true" : "false");
   traceMsg(TR::comp(), "\t_isInstanceOf=%s\n", _isInstanceOf ? "true" : "false");
   }

bool TR::SystemClassByNameRecord::isLessThanWithinKind(SymbolValidationRecord *other)
   {
   TR::SystemClassByNameRecord *rhs = downcast(this, other);
   // Don't compare _classChain - it's determined by _class
   return LexicalOrder::by(_class, rhs->_class).less();
   }

void TR::SystemClassByNameRecord::printFields()
   {
   traceMsg(TR::comp(), "SystemClassByNameRecord\n");
   TR::ClassValidationRecordWithChain::printFields();
   }

bool TR::ClassFromITableIndexCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ClassFromITableIndexCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::ClassFromITableIndexCPRecord::printFields()
   {
   traceMsg(TR::comp(), "ClassFromITableIndexCPRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::DeclaringClassFromFieldOrStaticRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::DeclaringClassFromFieldOrStaticRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::DeclaringClassFromFieldOrStaticRecord::printFields()
   {
   traceMsg(TR::comp(), "DeclaringClassFromFieldOrStaticRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::ConcreteSubClassFromClassRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ConcreteSubClassFromClassRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_childClass, rhs->_childClass)
      .thenBy(_superClass, rhs->_superClass).less();
   }

void TR::ConcreteSubClassFromClassRecord::printFields()
   {
   traceMsg(TR::comp(), "ConcreteSubClassFromClassRecord\n");
   traceMsg(TR::comp(), "\t_childClass=0x%p\n", _childClass);
   traceMsg(TR::comp(), "\t_superClass=0x%p\n", _superClass);
   }

bool TR::ClassChainRecord::isLessThanWithinKind(SymbolValidationRecord *other)
   {
   TR::ClassChainRecord *rhs = downcast(this, other);
   // Don't compare _classChain - it's determined by _class
   return LexicalOrder::by(_class, rhs->_class).less();
   }

void TR::ClassChainRecord::printFields()
   {
   traceMsg(TR::comp(), "ClassChainRecord\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_classChainOffset=%" OMR_PRIuPTR "\n", _classChainOffset);
   }

bool TR::MethodFromClassRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::MethodFromClassRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_index, rhs->_index).less();
   }

void TR::MethodFromClassRecord::printFields()
   {
   traceMsg(TR::comp(), "MethodFromClassRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_index=%u\n", _index);
   }

bool TR::StaticMethodFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::StaticMethodFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::StaticMethodFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "StaticMethodFromCPRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::SpecialMethodFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::SpecialMethodFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::SpecialMethodFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "SpecialMethodFromCPRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::VirtualMethodFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::VirtualMethodFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::VirtualMethodFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "VirtualMethodFromCPRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::VirtualMethodFromOffsetRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::VirtualMethodFromOffsetRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_virtualCallOffset, rhs->_virtualCallOffset)
      .thenBy(_ignoreRtResolve, rhs->_ignoreRtResolve).less();
   }

void TR::VirtualMethodFromOffsetRecord::printFields()
   {
   traceMsg(TR::comp(), "VirtualMethodFromOffsetRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_virtualCallOffset=%d\n", _virtualCallOffset);
   traceMsg(TR::comp(), "\t_ignoreRtResolve=%s\n", _ignoreRtResolve ? "true" : "false");
   }

bool TR::InterfaceMethodFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::InterfaceMethodFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_lookup, rhs->_lookup)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::InterfaceMethodFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "InterfaceMethodFromCPRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_lookup=0x%p\n", _lookup);
   printClass(_lookup);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::MethodFromClassAndSigRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::MethodFromClassAndSigRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_lookupClass, rhs->_lookupClass)
      .thenBy(_beholder, rhs->_beholder).less();
   }

void TR::MethodFromClassAndSigRecord::printFields()
   {
   traceMsg(TR::comp(), "MethodFromClassAndSigRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_methodClass=0x%p\n", _lookupClass);
   printClass(_lookupClass);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   }

bool TR::StackWalkerMaySkipFramesRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::StackWalkerMaySkipFramesRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_methodClass, rhs->_methodClass)
      .thenBy(_skipFrames, rhs->_skipFrames).less();
   }

void TR::StackWalkerMaySkipFramesRecord::printFields()
   {
   traceMsg(TR::comp(), "StackWalkerMaySkipFramesRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_methodClass=0x%p\n", _methodClass);
   printClass(_methodClass);
   traceMsg(TR::comp(), "\t_skipFrames=%sp\n", _skipFrames ? "true" : "false");
   }

bool TR::ClassInfoIsInitialized::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ClassInfoIsInitialized *rhs = downcast(this, other);
   return LexicalOrder::by(_class, rhs->_class)
      .thenBy(_isInitialized, rhs->_isInitialized).less();
   }

void TR::ClassInfoIsInitialized::printFields()
   {
   traceMsg(TR::comp(), "ClassInfoIsInitialized\n");
   traceMsg(TR::comp(), "\t_class=0x%p\n", _class);
   printClass(_class);
   traceMsg(TR::comp(), "\t_isInitialized=%sp\n", _isInitialized ? "true" : "false");
   }

bool TR::MethodFromSingleImplementer::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::MethodFromSingleImplementer *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_thisClass, rhs->_thisClass)
      .thenBy(_cpIndexOrVftSlot, rhs->_cpIndexOrVftSlot)
      .thenBy(_callerMethod, rhs->_callerMethod)
      .thenBy(_useGetResolvedInterfaceMethod, rhs->_useGetResolvedInterfaceMethod)
      .less();
   }

void TR::MethodFromSingleImplementer::printFields()
   {
   traceMsg(TR::comp(), "MethodFromSingleImplementer\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_thisClass=0x%p\n", _thisClass);
   printClass(_thisClass);
   traceMsg(TR::comp(), "\t_cpIndexOrVftSlot=%d\n", _cpIndexOrVftSlot);
   traceMsg(TR::comp(), "\t_callerMethod=0x%p\n", _callerMethod);
   traceMsg(TR::comp(), "\t_useGetResolvedInterfaceMethod=%d\n", _useGetResolvedInterfaceMethod);
   }

bool TR::MethodFromSingleInterfaceImplementer::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::MethodFromSingleInterfaceImplementer *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_thisClass, rhs->_thisClass)
      .thenBy(_cpIndex, rhs->_cpIndex)
      .thenBy(_callerMethod, rhs->_callerMethod).less();
   }

void TR::MethodFromSingleInterfaceImplementer::printFields()
   {
   traceMsg(TR::comp(), "MethodFromSingleInterfaceImplementer\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_thisClass=0x%p\n", _thisClass);
   printClass(_thisClass);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   traceMsg(TR::comp(), "\t_callerMethod=0x%p\n", _callerMethod);
   }

bool TR::MethodFromSingleAbstractImplementer::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::MethodFromSingleAbstractImplementer *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_thisClass, rhs->_thisClass)
      .thenBy(_vftSlot, rhs->_vftSlot)
      .thenBy(_callerMethod, rhs->_callerMethod).less();
   }

void TR::MethodFromSingleAbstractImplementer::printFields()
   {
   traceMsg(TR::comp(), "MethodFromSingleAbstractImplementer\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_thisClass=0x%p\n", _thisClass);
   printClass(_thisClass);
   traceMsg(TR::comp(), "\t_vftSlot=%d\n", _vftSlot);
   traceMsg(TR::comp(), "\t_callerMethod=0x%p\n", _callerMethod);
   }

bool TR::ImproperInterfaceMethodFromCPRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::ImproperInterfaceMethodFromCPRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_beholder, rhs->_beholder)
      .thenBy(_cpIndex, rhs->_cpIndex).less();
   }

void TR::ImproperInterfaceMethodFromCPRecord::printFields()
   {
   traceMsg(TR::comp(), "ImproperInterfaceMethodFromCPRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_beholder=0x%p\n", _beholder);
   printClass(_beholder);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   }

bool TR::J2IThunkFromMethodRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::J2IThunkFromMethodRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_thunk, rhs->_thunk)
      .thenBy(_method, rhs->_method).less();
   }

void TR::J2IThunkFromMethodRecord::printFields()
   {
   traceMsg(TR::comp(), "J2IThunkFromMethodRecord\n");
   traceMsg(TR::comp(), "\t_thunk=0x%p\n", _thunk);
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   }

bool TR::IsClassVisibleRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::IsClassVisibleRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_sourceClass, rhs->_sourceClass)
      .thenBy(_destClass, rhs->_destClass)
      .thenBy(_isVisible, rhs->_isVisible).less();
   }

void TR::IsClassVisibleRecord::printFields()
   {
   traceMsg(TR::comp(), "IsClassVisibleRecord\n");
   traceMsg(TR::comp(), "\t_sourceClass=0x%p\n", _sourceClass);
   printClass(_sourceClass);
   traceMsg(TR::comp(), "\t_destClass=0x%p\n", _destClass);
   printClass(_destClass);
   traceMsg(TR::comp(), "\t_isVisible=%s\n", _isVisible ? "true" : "false");
   }

bool TR::DynamicMethodFromCallsiteIndexRecord::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::DynamicMethodFromCallsiteIndexRecord *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_caller, rhs->_caller)
      .thenBy(_callsiteIndex, rhs->_callsiteIndex)
      .thenBy(_appendixObjectNull, rhs->_appendixObjectNull).less();
   }

void TR::DynamicMethodFromCallsiteIndexRecord::printFields()
   {
   traceMsg(TR::comp(), "DynamicMethodFromCallsiteIndexRecord\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_caller=0x%p\n", _caller);
   traceMsg(TR::comp(), "\t_callsiteIndex=%d\n", _callsiteIndex);
   traceMsg(TR::comp(), "\t_appendixObjectNull=%s\n", _appendixObjectNull ? "true" : "false");
   }

bool TR::HandleMethodFromCPIndex::isLessThanWithinKind(
   SymbolValidationRecord *other)
   {
   TR::HandleMethodFromCPIndex *rhs = downcast(this, other);
   return LexicalOrder::by(_method, rhs->_method)
      .thenBy(_caller, rhs->_caller)
      .thenBy(_cpIndex, rhs->_cpIndex)
      .thenBy(_appendixObjectNull, rhs->_appendixObjectNull).less();
   }

void TR::HandleMethodFromCPIndex::printFields()
   {
   traceMsg(TR::comp(), "HandleMethodFromCPIndex\n");
   traceMsg(TR::comp(), "\t_method=0x%p\n", _method);
   traceMsg(TR::comp(), "\t_caller=0x%p\n", _caller);
   traceMsg(TR::comp(), "\t_cpIndex=%d\n", _cpIndex);
   traceMsg(TR::comp(), "\t_appendixObjectNull=%s\n", _appendixObjectNull ? "true" : "false");
   }
