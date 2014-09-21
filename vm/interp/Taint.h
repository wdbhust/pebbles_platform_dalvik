/*
 * Copyright (c) 2010 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Authors: William Enck <enck@cse.psu.edu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Dalvik interpreter public definitions.
 */
#ifndef _DALVIK_INTERP_TAINT
#define _DALVIK_INTERP_TAINT

#include <asm/byteorder.h>

/* The Taint structure */
/*
 * multitaint 0 - not multitainted (guid will be the original guid)
 *            1 - multi-taint (guid will be an indirect local-JVM id
 *                that points to the gDvm.multiTaintTable.
 * guid       either the application provided guid or an indirect id.
 */

#define TAINT_BIT_MULTI_TAINT 1
#define TAINT_BIT_PRIMARY_KEY 1
#define TAINT_BIT_GUID        30

typedef struct Taint {
    struct {
#ifdef __BIG_ENDIAN_BITFIELD
        u4 multiTaint: TAINT_BIT_MULTI_TAINT;
        u4 guid:       TAINT_BIT_GUID;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
        u4 guid:       TAINT_BIT_GUID;
        u4 multiTaint: TAINT_BIT_MULTI_TAINT;
#else
#error "ByteOrder Error: <asm/byteorder.h>"
#endif
    };
    u4 tag;
} Taint;

/* The Taint markings */

#define TAINT_CLEAR         ((u4)0x00000000) /* No taint */
#define TAINT_LOCATION      ((u4)0x00000000) /* Location */
#define TAINT_CONTACTS      ((u4)0x00000000) /* Address Book (ContactsProvider) */
#define TAINT_MIC           ((u4)0x00000000) /* Microphone Input */
#define TAINT_PHONE_NUMBER  ((u4)0x00000000) /* Phone Number */
#define TAINT_LOCATION_GPS  ((u4)0x00000000) /* GPS Location */
#define TAINT_LOCATION_NET  ((u4)0x00000000) /* NET-based Location */
#define TAINT_LOCATION_LAST ((u4)0x00000000) /* Last known Location */
#define TAINT_CAMERA        ((u4)0x00000000) /* camera */
#define TAINT_ACCELEROMETER ((u4)0x00000000) /* accelerometer */
#define TAINT_SMS           ((u4)0x00000000) /* SMS */
#define TAINT_IMEI          ((u4)0x00000000) /* IMEI */
#define TAINT_IMSI          ((u4)0x00000000) /* IMSI */
#define TAINT_ICCID         ((u4)0x00000000) /* ICCID (SIM card identifier) */
#define TAINT_DEVICE_SN     ((u4)0x00000000) /* Device serial number */
#define TAINT_ACCOUNT       ((u4)0x00000000) /* User account information */
#define TAINT_HISTORY       ((u4)0x00000000) /* browser history */

extern u4 dvmMultiTaintTableLookupAndCreateByCombinedGuids(
        u4 taint1, u4 taint2);

INLINE u4 COMBINE_TAINT_TAGS(u4 origTag, u4 newTag)
{
    if (origTag == newTag) return origTag;
    else if (origTag == TAINT_CLEAR) return newTag;
    else if (newTag == TAINT_CLEAR) return origTag;

    /* Mutltitaint both taints are not clear. */
    Taint ret;
    ret.tag = TAINT_CLEAR;
    ret.multiTaint = 1;
    ret.guid = dvmMultiTaintTableLookupAndCreateByCombinedGuids(origTag,
            newTag);
    if (ret.guid == 0) { LOGE("Error combining guids!\n"); return origTag; }
    return ret.tag;
}

INLINE Taint COMBINE_TAINT(Taint origTaint, Taint newTaint)
{
    Taint returnTaint;
    returnTaint.tag = COMBINE_TAINT_TAGS(origTaint.tag, newTaint.tag);
    return returnTaint;
}

INLINE Taint CHOOSE_TAINT(Taint origTaint, Taint newTaint)
{
    return COMBINE_TAINT(origTaint, newTaint);
}

#endif /*_DALVIK_INTERP_TAINT*/
