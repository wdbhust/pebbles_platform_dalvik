#include "Dalvik.h"

#define MULTI_TAINT_UNUSED     0
#define MULTI_TAINT_USED       1
#define MULTI_TAINT_TO_DELETE  2

typedef struct MultiTaint {
    u4 id;
    int numGuids;
    u4* guids;
} MultiTaint;

void multiTaintFree(MultiTaint* multiTaint);
MultiTaint* multiTaintDup(const MultiTaint* multiTaint);
void multiTaintPrint(const MultiTaint* multiTaint, int printGuids,
                     char* buf, int bufLen);
int mergeTaints(u4* guids1, int numGuids1, u4* guids2, int numGuids2,
                u4* combinedGuids, int numCombinedGuids,
                u4* hash);
static int toDeleteTaintFilterWithoutFree(void* item);
static int toDeleteTaintFilterWithFree(void* item);
static int multiTaintCmpByGuids(const void* tableItem, const void* looseItem);
static int multiTaintCmpById(const void* tableItem, const void* looseItem);
static void noopItemFree(void* mt);
u4 getUnusedMultiTaintId();

INLINE u4 fromMultiTaintIndexToId(int index) { return (u4)(index + 1); }
INLINE int fromMultiTaintIdToIndex(u4 id) { return (((int)id) - 1); }

extern void dvmTaintTimerInvokeHookedGC();

/*
 * Initialize the multi-taint table.
 */
bool dvmMultiTaintTableStartup(void)
{
    if (gDvm.multiTaintTable.initialized) return false;
    //LOGD("dvmMultiTaintTableStartup start\n");
    bool ret = false;
    gDvm.multiTaintTable.indexById = gDvm.multiTaintTable.indexByGuids = NULL;

    gDvm.multiTaintTable.unusedIndexHint = 0;
    gDvm.multiTaintTable.indexById = dvmHashTableCreate(
            dvmHashSize(NUM_MULTI_TAINTS),
            noopItemFree);
    if (gDvm.multiTaintTable.indexById == NULL) goto END;
    gDvm.multiTaintTable.indexByGuids = dvmHashTableCreate(
            dvmHashSize(NUM_MULTI_TAINTS),
            noopItemFree);
    if (gDvm.multiTaintTable.indexByGuids == NULL) {
        dvmHashTableFree(gDvm.multiTaintTable.indexById);
        goto END;
    }
    gDvm.multiTaintTable.lock = gDvm.multiTaintTable.indexById;
    memset(gDvm.multiTaintTable.usedMultiTaintIds, MULTI_TAINT_UNUSED,
           sizeof(gDvm.multiTaintTable.usedMultiTaintIds));
    gDvm.multiTaintTable.initialized = true;
    ret = true;
END:
    //LOGD("dvmMultiTaintTableStartup end\n");
    return ret;
}

/*
 * Marks multi-taint id as used.
 * This function is called by the GC for each multi-taint that's found.
 */
void dvmMultiTaintTableMarkIdAsUsed(u4 id)
{
    if (!gDvm.multiTaintTable.initialized) return;
    if (id > 0 && id <= NUM_MULTI_TAINTS) {
        gDvm.multiTaintTable.usedMultiTaintIds[fromMultiTaintIdToIndex(id)] =
            MULTI_TAINT_USED;
    } else {
        LOGE("Error: Bad multi taint ID to mark as used.");
    }
}

/*
 * Same as dvmMultiTaintTableMarkAllForDeletion, but it is not
 * thread-safe. It should be called while holding a lock for
 * exclusive access to gDvm.multiTaintTable.usedMultiTaintIds (e.g.,
 * gDvm.multiTaintTable.lock).
 */
void markAllForDeletion(bool markUsedOnly)
{
    int i;
    for (i = 0; i < NUM_MULTI_TAINTS; ++i) {
       if (! markUsedOnly ||
           gDvm.multiTaintTable.usedMultiTaintIds[i] == MULTI_TAINT_USED) {
           gDvm.multiTaintTable.usedMultiTaintIds[i] = MULTI_TAINT_TO_DELETE;
       }
    }
}

/*
 * Marks items for deletion. If markUsedOnly is true, it will only mark for
 * deletion those items that were previously marked as used.
 * If markUsedOnly is false, it will mark all objects for deletion.
 * Example usages of this function are: before GC (markUsedOnly = true) or
 * during teardown (markUsedOnly = false).
 *
 */
void dvmMultiTaintTableMarkAllForDeletion(bool markUsedOnly)
{
    if (!gDvm.multiTaintTable.initialized) return;
    //LOGD("dvmMultiTaintTableMarkAllForDeletion start\n");
    dvmHashTableLock(gDvm.multiTaintTable.lock);
    markAllForDeletion(markUsedOnly);
    dvmHashTableUnlock(gDvm.multiTaintTable.lock);
    //LOGD("dvmMultiTaintTableMarkAllForDeletion end\n");
}

/*
 * Same as dvmMultiTaintTableRemoveItemsMarkedForDeletion except
 * that it is not thread-safe. It should be called while holding
 * a lock for exclusive access to gDvm.multiTaintTable.indexById
 * and gDvm.multiTaintTable.indexByGuids (e.g., Dvm.multiTaintTable.lock).
 */
void removeItemsMarkedForDeletion(void)
{
    dvmHashForeachRemove(gDvm.multiTaintTable.indexById,
                         toDeleteTaintFilterWithoutFree);
    dvmHashForeachRemove(gDvm.multiTaintTable.indexByGuids,
                         toDeleteTaintFilterWithFree);
}

/*
 * Removes items that are left scheduled for delete after a GC session.
 * One example use of this function is after the GC.
 */
void dvmMultiTaintTableRemoveItemsMarkedForDeletion(void)
{
    if (!gDvm.multiTaintTable.initialized) return;
    //LOGD("dvmMultiTaintTableRemoveItemsMarkedForDeletion start\n");
    dvmHashTableLock(gDvm.multiTaintTable.lock);
    removeItemsMarkedForDeletion();
    dvmHashTableUnlock(gDvm.multiTaintTable.lock);
    //LOGD("dvmMultiTaintTableRemoveItemsMarkedForDeletion end\n");
}

/*
 * Looks up a multi-taint by its id. It returns the guids that form
 * that multi-taint in parameter "guids" and the number of these
 * guids in numGuids.
 *
 * Returns true iff a multi-taint with that id was found.
 */
bool dvmMultiTaintTableLookupById(u4 taintId, u4** guids, int* numGuids)
{
    if (!gDvm.multiTaintTable.initialized) return false;
    //LOGD("dvmMultiTaintTableLookupById start\n");
    bool ret = false;
    if (guids) *guids = NULL;
    if (numGuids) *numGuids = 0;

    MultiTaint lookFor;
    lookFor.id = taintId;
    dvmHashTableLock(gDvm.multiTaintTable.lock);
    MultiTaint* val = dvmHashTableLookup(gDvm.multiTaintTable.indexById,
        taintId,
        (void *)&lookFor,
        (HashCompareFunc)multiTaintCmpById,
        false);
    if (val == NULL) {
        if (MULTITAINT_DEBUG_PRINT)
            LOGE("val = null\n");
        goto UNLOCK;
    }

    if (guids) *guids = val->guids;
    if (numGuids) *numGuids = val->numGuids;
    ret = true;
UNLOCK:
    dvmHashTableUnlock(gDvm.multiTaintTable.lock);
END:
    //LOGD("dvmMultiTaintTableLookupById end\n");
    return ret;
}

/*
 * Looks up the multi-taint for the multi-taint composed of t1 and t2.
 * If missing, it creates the multi-taint.
 * Returns the ID of that taint, which is always non-zero. In case
 * of error, it returns an ID of 0.
 */
u4 dvmMultiTaintTableLookupAndCreateByCombinedGuids(u4 t1, u4 t2)
{
    if (!gDvm.multiTaintTable.initialized) return 0;  // 0 indicates error.
    //LOGD("dvmMultiTaintTableLookupAndCreateByCombinedGuids start\n");
    Taint taint1, taint2;
    taint1.tag = t1;
    taint2.tag = t2;
    // assert(taint1.tag != taint2.tag && taint1.tag != TAINT_CLEAR &&
    //        taint2.tag != TAINT_CLEAR);

    u4 ret = 0;  // id to return; a value of 0 indicates erend

    u4 g1 = taint1.guid, g2 = taint2.guid;
    u4* guids1 = &g1, *guids2 = &g2;
    int numGuids1 = 1, numGuids2 = 1;

    // If either taint is a multi-taint, resolve it while it's still available.
    if (taint1.multiTaint &&
        (! dvmMultiTaintTableLookupById(taint1.guid, &guids1, &numGuids1) ||
         guids1 == NULL)) {
    	if(MULTITAINT_DEBUG_PRINT)
    		LOGE("MultiTaint unable to identify guids for multitaint %d (id=%d)\n",
    				taint1.tag, taint1.guid);
        //LOGD("dvmMultiTaintTableLookupAndCreateByCombinedGuids end\n");
        return taint2.tag;
    }
    if (taint2.multiTaint &&
        (! dvmMultiTaintTableLookupById(taint2.guid, &guids2, &numGuids2) ||
         guids2 == NULL)) {
    	if(MULTITAINT_DEBUG_PRINT)
    		LOGE("MultiTaint unable to identify guids for multitaint %d (id=%d)\n",
    				taint2.tag, taint2.guid);
       //LOGD("dvmMultiTaintTableLookupAndCreateByCombinedGuids end\n");
       return taint1.tag;
    }

    // Combine the two taints into a multi-taint.
    MultiTaint multiTaint;
    int numCombinedGuids = numGuids1 + numGuids2;
    u4 combinedGuids[numCombinedGuids], guidsHash;
    numCombinedGuids = mergeTaints(guids1, numGuids1, guids2, numGuids2,
                                   combinedGuids, numCombinedGuids,
                                   &guidsHash);
    multiTaint.id = 0;  // dunno it yet, that's what I'm looking for.
    multiTaint.guids = combinedGuids;
    multiTaint.numGuids = numCombinedGuids;

    // Search for the multi-taint and if we can't find it, add it.
    dvmHashTableLock(gDvm.multiTaintTable.lock);
    const MultiTaint* val = dvmHashTableLookup(
            gDvm.multiTaintTable.indexByGuids,
            guidsHash,
            (void *)&multiTaint,
            (HashCompareFunc)multiTaintCmpByGuids,
            false);
    if (val == NULL) {  // multi-taint doesn't exist; create and add it.
        MultiTaint* newMultiTaint = multiTaintDup(&multiTaint);
        if (newMultiTaint == NULL) {  // Presumably no unused ID found.
                                      // Pretty ugly check here...
            // Run the GC, but not before I unlock the lock.
            dvmHashTableUnlock(gDvm.multiTaintTable.lock);
            LOGE("Running GC explicitly to eliminate unused multi-taints.\n");
            /*
             * TODO: can we do this without the taint timer?
             * dvmTaintTimerInvokeHookedGC();
             */
            LOGE("Explicit GC to eliminate unused multi-taints has finished.\n");
            dvmHashTableLock(gDvm.multiTaintTable.lock);
            newMultiTaint = multiTaintDup(&multiTaint);
            if (newMultiTaint == NULL) goto UNLOCK;
        }
        // newMultiTaint != NULL here.
        if (MULTITAINT_DEBUG_PRINT)
            LOGE("Adding new multiTaints to table.\n");
        dvmHashTableLookup(gDvm.multiTaintTable.indexByGuids, guidsHash,
                           (void*)newMultiTaint,
                           (HashCompareFunc)multiTaintCmpByGuids,
                           true);
        dvmHashTableLookup(gDvm.multiTaintTable.indexById, newMultiTaint->id,
                           (void*)newMultiTaint,
                           (HashCompareFunc)multiTaintCmpById,
                           true);
        ret = newMultiTaint->id;
    } else {  // multi-taint already exists; use its id.
        ret = val->id;
    }

UNLOCK:
    dvmHashTableUnlock(gDvm.multiTaintTable.lock);
    if(MULTITAINT_DEBUG_PRINT)
    	LOGD("Obtained multi-taint combining taints %d (multitaint=%d) and %d (multitaint=%d). \
Its id is %d and it is %snew.\n",
         taint1, taint1.multiTaint, taint2, taint2.multiTaint,
         ret, (val ? "not " : ""));

    //LOGD("dvmMultiTaintTableLookupAndCreateByCombinedGuids end\n");
    return ret;
}

void dvmMultiTaintTablePrintStats(int fd)
{
    char msg[256], msgLen;
    if (!gDvm.multiTaintTable.initialized) return;
    msgLen = snprintf(msg, 256, "Number of active multi-taints: %d\n",
                      dvmHashTableNumEntries(gDvm.multiTaintTable.indexById));
    if (fd > 0) write(fd, msg, msgLen);
    LOGI("%s", msg);
}

/*
 * De-allocate the multi-taint table and all of its data.
 * The data is deallocated automatically by the hashtable function.
 */
bool dvmMultiTaintTableTeardown(void)
{
    if (!gDvm.multiTaintTable.initialized) return false;
    //LOGD("dvmMultiTaintTableTeardown start\n");

    // Remove all elements correctly.
    dvmHashTableLock(gDvm.multiTaintTable.lock);
    markAllForDeletion(false);
    removeItemsMarkedForDeletion();
    dvmHashTableUnlock(gDvm.multiTaintTable.lock);

    // Free the table (table has no elements now).
    dvmHashTableFree(gDvm.multiTaintTable.indexById);
    dvmHashTableFree(gDvm.multiTaintTable.indexByGuids);
    gDvm.multiTaintTable.initialized = false;

    //LOGD("dvmMultiTaintTableTeardown end\n");
    return true;
}

/*
 * Deletes an entry from the multi taint table.
 */
void dvmMultiTaintTableRemoveMultiTaint(u4 t1)
{
    Taint taint;
    taint.tag = t1;
    if (taint.multiTaint) {
        u4 taintId = taint.guid;
        u4 guid = taint.guid;
        u4* guids = &guid;
        int guidCount = 0;
        if (dvmMultiTaintTableLookupById(taint.guid, &guids, &guidCount)) {
            if (MULTITAINT_DEBUG_PRINT)
                LOGE("dvmMultiTaintTableRemoveMultiTaint: %d\n", taintId);
            int index;

            index = fromMultiTaintIdToIndex(taintId);
            dvmHashTableLock(gDvm.multiTaintTable.lock);
            gDvm.multiTaintTable.usedMultiTaintIds[index] =
                MULTI_TAINT_TO_DELETE;
            dvmHashTableUnlock(gDvm.multiTaintTable.lock);
            dvmMultiTaintTableRemoveItemsMarkedForDeletion();
        } else if (MULTITAINT_DEBUG_PRINT) {
            LOGE("Not a multitaint to remove: %d\n", t1);
        }
    }

}

/*
 * dvmHashTableRemoveForeach callback function that filters the
 * items that should be deleted.
 *
 * Returns 1 for each multi-taint item that's marked for deletion.
 * Returns 0 for all other taints.
 * Does not actually deallocate any items or mark them as unused.
 */
static int toDeleteTaintFilterWithoutFree(void* item)
{
    int index = fromMultiTaintIdToIndex(((MultiTaint*)item)->id);
    bool toRemove = (gDvm.multiTaintTable.usedMultiTaintIds[index] ==
            MULTI_TAINT_TO_DELETE);
    if (toRemove && MULTITAINT_DEBUG_PRINT) {
        LOGD("Removing formerly used, currently unused multitaint guid %d\n",
             ((MultiTaint*)item)->id);
    }
    return toRemove;
}

/*
 * The same functioning and return values as for
 * toDeleteTaintFilterWithoutFree, but this function also
 * deallocates and marks as unused any items that are marked for deletion.
 */
static int toDeleteTaintFilterWithFree(void* item)
{
    int index = fromMultiTaintIdToIndex(((MultiTaint*)item)->id);
    bool toRemove =
        (gDvm.multiTaintTable.usedMultiTaintIds[index] == MULTI_TAINT_TO_DELETE);
    if (toRemove) {
        gDvm.multiTaintTable.usedMultiTaintIds[index] = MULTI_TAINT_UNUSED;
        multiTaintFree((MultiTaint*)item);
    }
    return toRemove;
}

INLINE void hashInts(u4 i1, u4 i2, u4* result) { *result = i1 + i2; }

/*
 * Merges the guids to produce a new set of guids.
 * Input gui arrays are assumed to be sorted, and the output will
 * be sorted.
 */
int mergeTaints(u4* guids1, int numGuids1, u4* guids2, int numGuids2,
                u4* combinedGuids, int numCombinedGuids, u4* hash)
{
    if (hash) *hash = 0;
    int i1, i2, i;
    for (i1 = i2 = i = 0;
         (i1 < numGuids1 && i2 < numGuids2 && i < numCombinedGuids);
         ++i) {
        if (guids1[i1] < guids2[i2]) combinedGuids[i] = guids1[i1++];
        else if (guids1[i1] > guids2[i2]) combinedGuids[i] = guids2[i2++];
        else { combinedGuids[i] = guids1[i1++]; ++i2; }
        if (hash) hashInts(*hash, combinedGuids[i], hash);
    }
    for (; i1 < numGuids1 && i < numCombinedGuids; ++i1, ++i) {
        combinedGuids[i] = guids1[i1];
        if (hash) hashInts(*hash, combinedGuids[i], hash);
    }
    for (; i2 < numGuids2 && i < numCombinedGuids; ++i2, ++i) {
        combinedGuids[i] = guids2[i2];
        if (hash) hashInts(*hash, combinedGuids[i], hash);
    }
    return i;  // this is the actual number of guids.
}

/*
 * Compares multi-taints by their guids lists.
 */
static int multiTaintCmpByGuids(const void* tableItem, const void* looseItem)
{
    MultiTaint* tableTaint = ((MultiTaint *)tableItem);
    MultiTaint* looseTaint  = ((MultiTaint *)looseItem);
    if (tableTaint == NULL || looseTaint == NULL) return -1;
    if (tableTaint->numGuids != looseTaint->numGuids) {
        return tableTaint->numGuids - looseTaint->numGuids;
    }
    return memcmp(tableTaint->guids, looseTaint->guids,
                  tableTaint->numGuids * sizeof(u4));
}

/*
 * Compares multi-taints by id.
 */
static int multiTaintCmpById(const void* tableItem, const void* looseItem)
{
    return ((MultiTaint *)tableItem)->id - ((MultiTaint *)looseItem)->id;
}

/*
 * Gets the next unused multi-taint id.
 * Assumes exclusive lock was taken before.
 */
u4 getUnusedMultiTaintId()
{
    int i;
    for (i = gDvm.multiTaintTable.unusedIndexHint; i < NUM_MULTI_TAINTS; ++i) {
        if (gDvm.multiTaintTable.usedMultiTaintIds[i] == MULTI_TAINT_UNUSED) {
            gDvm.multiTaintTable.usedMultiTaintIds[i] = MULTI_TAINT_USED;
            gDvm.multiTaintTable.unusedIndexHint = (i+1) % NUM_MULTI_TAINTS;
            return fromMultiTaintIndexToId(i);
        }
    }
    // Not found yet. Look from the beginning, too, maybe something's
    // cleared up.
    for (i = 0; i < gDvm.multiTaintTable.unusedIndexHint; ++i) {
        if (gDvm.multiTaintTable.usedMultiTaintIds[i] == MULTI_TAINT_UNUSED) {
            gDvm.multiTaintTable.usedMultiTaintIds[i] = MULTI_TAINT_USED;
            gDvm.multiTaintTable.unusedIndexHint = (i+1) % NUM_MULTI_TAINTS;
            return fromMultiTaintIndexToId(i);
        }
    }
    LOGD("No unused multitaint found\n");
    return 0;
}

MultiTaint* multiTaintNew()
{
    MultiTaint* newMultiTaint = (MultiTaint*)malloc(sizeof(MultiTaint));
    if (newMultiTaint == NULL) return NULL;
    newMultiTaint->numGuids = 0;
    newMultiTaint->guids = NULL;
    newMultiTaint->id = 0;
    return newMultiTaint;
}
/*
 * Copies a multi-taint into a new one that's dynamically allocated.
 * Everything is copied, except for the ID, which is newly generated.
 */
MultiTaint* multiTaintDup(const MultiTaint* multiTaint)
{
    MultiTaint* newMultiTaint = multiTaintNew();
    if (newMultiTaint == NULL) return NULL;

    int id = getUnusedMultiTaintId();
    if (id == 0) goto error;

    newMultiTaint->id       = id;
    newMultiTaint->numGuids = multiTaint->numGuids;
    newMultiTaint->guids    = (u4*)malloc(newMultiTaint->numGuids * sizeof(u4));
    if (newMultiTaint->guids == NULL) goto error;
    memcpy(newMultiTaint->guids, multiTaint->guids,
           newMultiTaint->numGuids * sizeof(u4));

    return newMultiTaint;

error:
    multiTaintFree(newMultiTaint);
    return NULL;
}

void multiTaintPrint(const MultiTaint* multiTaint, int numGuidsToPrint,
                     char* buf, int bufLen)
{
    int n;
    if (multiTaint == NULL) {
        snprintf(buf, bufLen, "multitaint null");
        n = strlen(buf); buf += n; bufLen -= n;
        return;
    }
    snprintf(buf, bufLen, "multitaint id=%d (numGuids=%d",
             multiTaint->id, multiTaint->numGuids);
    n = strlen(buf); buf += n; bufLen -= n;
    if (numGuidsToPrint > 0) {
        int i;
        snprintf(buf, bufLen, ", guids=[ ");
        n = strlen(buf); buf += n; bufLen -= n;
        for (i = 0;
             i < multiTaint->numGuids && i < numGuidsToPrint && bufLen > 0;
             ++i) {
            snprintf(buf, bufLen, "%d ", multiTaint->guids[i]);
            n = strlen(buf); buf += n; bufLen -= n;
        }
        if (i < multiTaint->numGuids) {
            snprintf(buf, bufLen, "...");
            n = strlen(buf); buf += n; bufLen -= n;
        }
        snprintf(buf, bufLen, "]");
        n = strlen(buf); buf += n; bufLen -= n;
    }
    snprintf(buf, bufLen, ")");
    n = strlen(buf); buf += n; bufLen -= n;
}

/*
 * Frees a multi-taint structure.
 */
void multiTaintFree(MultiTaint* multiTaint)
{
    if (multiTaint == NULL) return;
    if (multiTaint->guids != NULL) free(multiTaint->guids);
    free(multiTaint);
}

static void noopItemFree(void* mt)
{
    // We don't want to deallocate entries automatically,
    // as we have shared pointers between the entries in
    // the two tables. We need to deallocate them smartly.
}

