/*
 * Multi-taint table that maps taint combinations to ids.
 */
#ifndef _DALVIK_MULTITAINTTABLE
#define _DALVIK_MULTITAINTTABLE

#define MULTITAINT_DEBUG_PRINT 0
// Initialization and teardown.
bool dvmMultiTaintTableStartup(void);
bool dvmMultiTaintTableTeardown(void);

// GC-related functions.
void dvmMultiTaintTableMarkIdAsUsed(u4 id);
void dvmMultiTaintTableMarkAllUsedForDeletion(void);
void dvmMultiTaintTableRemoveItemsMarkedForDeletion(void);

// Access functions.
bool dvmMultiTaintTableLookupById(u4 taintId, u4** guids, int* numGuids);
u4 dvmMultiTaintTableLookupAndCreateByCombinedGuids(u4 taint1, u4 taint2);

// Stats.
void dvmMultiTaintTablePrintStats(int fd);

// Deletion Functions
void dvmMultiTaintTableRemoveMultiTaint(u4 taint1);

#endif /*_DALVIK_MULTITAINTTABLE*/
