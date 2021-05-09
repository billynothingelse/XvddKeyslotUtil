#pragma once

#define MAX_KEY_ENTRIES 255

#pragma pack(push, 1)

/// <summary>
/// Represents a slot that contains encryption key
/// GUID and 4-byte padding
/// </summary>
struct SCP_GUID_SLOT
{
    GUID EncryptionKeyGUID;             //! 0x00 - Key associated w/ XVD
    uint32_t Padding;                   //! 0x10 - Padding
    /* size: 0x14 */
};

struct SCP_KEY_DATA { 
    BYTE Data[0x10];
};

/// <summary>
/// Represents a "single" data slot by combining both 
/// keyslots referenced by the stored license.
/// </summary>
struct SCP_KEY_SLOT {
    SCP_KEY_DATA SlotIdBegin;           //! 0x00 - Unknown
    SCP_KEY_DATA KeyDataBegin[29];      //! 0x10 - Data Key
    GUID Guid;                          //! 0x1E0 - ??
    SCP_KEY_DATA SlotIdEnd;             //! 0x1F0 - Unknown
    SCP_KEY_DATA KeyDataEnd[29];        //! 0x200 - Tweak Key
    BYTE Padding[0x20];                 //! 0x3D0 - Padding
    /* size: 0x3F0 */
};

/// <summary>
/// Represents a SCP keytable (GUIDs + Key data)
/// </summary>
struct SCP_KEY_TABLE {
    SCP_GUID_SLOT Guids[MAX_KEY_ENTRIES];   // 0x00
    SCP_KEY_SLOT KeySlots[MAX_KEY_ENTRIES]; // 0x13EC
    /* size: 0x3FFFC */
};

/// <summary>
/// Data layout for CIK exporting
/// </summary>
struct SCP_LICENSE {
    GUID KeyGUID;                     //! 0x00 - EncKey GUID
    SCP_KEY_DATA TweakKey;            //! 0x10 - AES Tweak Key
    SCP_KEY_DATA DataKey;             //! 0x20 - AES Data Key
    /* size: 0x30 */
};

#pragma pack(pop)
