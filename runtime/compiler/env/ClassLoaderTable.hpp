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

#ifndef CLASSLOADERTABLE_INCL
#define CLASSLOADERTABLE_INCL

#include "env/TRMemory.hpp"
#include "env/PersistentCollections.hpp"
#include "env/jittypes.h"


#define CLASSLOADERTABLE_SIZE 2053

class TR_J9SharedCache;
struct TR_ClassLoaderInfo;

class TR_PersistentClassLoaderTable
   {
public:

   TR_PERSISTENT_ALLOC(TR_Memory::PersistentCHTable)
   TR_PersistentClassLoaderTable(TR_PersistentMemory *persistentMemory);

   void associateClassLoaderWithClass(J9VMThread *vmThread, void *loader, TR_OpaqueClassBlock *clazz);
   void *lookupClassChainAssociatedWithClassLoader(void *loader) const;
   void *lookupClassLoaderAssociatedWithClassChain(void *chain) const;
#if defined(J9VM_OPT_JITSERVER)
   // JIT client needs to associate each class loader with the name of its first loaded class
   // in order to support AOT method serialization (and caching at JITServer) and deserialization.
   std::pair<void *, void *>// loader, chain
   lookupClassLoaderAndChainAssociatedWithClassName(const uint8_t *data, size_t length) const;
   void *lookupClassLoaderAssociatedWithClassName(const uint8_t *data, size_t length) const;
   const J9UTF8 *lookupClassNameAssociatedWithClassLoader(void *loader) const;
#endif /* defined(J9VM_OPT_JITSERVER) */
   void removeClassLoader(J9VMThread *vmThread, void *loader);

   TR_J9SharedCache *getSharedCache() const { return _sharedCache; }
   void setSharedCache(TR_J9SharedCache *sharedCache) { _sharedCache = sharedCache; }

private:

   friend class TR_Debug;

   TR_PersistentMemory *const _persistentMemory;
   TR_J9SharedCache *_sharedCache;

   TR_ClassLoaderInfo *_loaderTable[CLASSLOADERTABLE_SIZE];
   TR_ClassLoaderInfo *_chainTable[CLASSLOADERTABLE_SIZE];
#if defined(J9VM_OPT_JITSERVER)
   TR_ClassLoaderInfo *_nameTable[CLASSLOADERTABLE_SIZE];
#endif /* defined(J9VM_OPT_JITSERVER) */
   };

struct MethodEntry
   {
   uintptr_t _dependencyCount;
   const uintptr_t *_dependencyChain;
   };


struct OffsetEntry
   {
   uintptr_t _loadedClassCount;
   PersistentUnorderedSet<std::pair<J9Method *const, MethodEntry> *> _waitingMethods;
   };

struct ClassEntry
   {
   uintptr_t _classOffset;
   uintptr_t _classChainOffset;
   };

enum DependencyTrackingStatus
   {
   TrackingSuccessful,
   // CouldNotReduceCount,
   MethodCouldNotBeQueued,
   MethodWasntTracked
   };

// TODO: move to own file
class TR_AOTDependencyTable
   {
public:
   TR_PERSISTENT_ALLOC(TR_Memory::PersistentCHTable)
   TR_AOTDependencyTable(TR_PersistentMemory *persistentMemory);

   void setSharedCache(TR_J9SharedCache *sharedCache) { _sharedCache = sharedCache; }

   void trackStoredMethod(J9VMThread *vmThread, J9Method *method, const uintptr_t *dependencyChain, bool &dependenciesSatisfied);

   void onClassLoad(J9VMThread *vmThread, TR_OpaqueClassBlock *ramClass);
   void invalidateClass(TR_OpaqueClassBlock *ramClass);
   void stopTracking(J9Method *method);

   // TODO: probably remove this entirely!
   bool isTableActive() { return _sharedCache != NULL; }
   bool isMethodTracked(J9Method *method, uintptr_t &remainingDependencies);
   void printTrackingStatus(J9Method *method);

   DependencyTrackingStatus wasMethodPreviouslyTracked(J9Method *method);

   void dumpTableDetails();

private:
   bool queueAOTLoad(J9VMThread *vmThread, J9Method *method, uintptr_t offsetThatCausedQueue);
   void registerOffset(J9VMThread *vmThread, uintptr_t offset);
   void unregisterOffset(uintptr_t offset);

   TR::Monitor *const _tableMonitor;

   TR_PersistentMemory *const _persistentMemory;
   TR_J9SharedCache *_sharedCache;

   PersistentUnorderedMap<uintptr_t, OffsetEntry> _offsetMap; // TODO: must fill in rght types
   PersistentUnorderedMap<J9Method *, MethodEntry> _methodMap;
   PersistentUnorderedMap<J9Class *, ClassEntry> _classMap;

   // TODO: temporary debug thing.
   PersistentUnorderedMap<J9Method *, DependencyTrackingStatus> _previouslyTrackedMethods;
   };

#endif
