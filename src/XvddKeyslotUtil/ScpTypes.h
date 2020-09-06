#pragma once

#define MAX_GUID_SLOTS 255

#pragma pack(push, 1)

struct SCP_KEY_DATA { 
    BYTE Data[0x10];
};

/// <summary>
/// Represents a "single" data slot by combining both 
/// keyslots referenced by the stored license.
/// </summary>
struct SCP_KEY_SLOT {
    SCP_KEY_DATA SlotIdBegin;           //! Unknown
    SCP_KEY_DATA KeyDataBegin[29];      //! Data Key
    GUID Guid;                          //! ??
    SCP_KEY_DATA SlotIdEnd;             //! Unknown
    SCP_KEY_DATA KeyDataEnd[29];        //! Tweak Key
    BYTE Padding[0x20];                 //! Padding
};

/// <summary>
/// Data layout for CIK exporting
/// </summary>
struct SCP_LICENSE {
    GUID KeyGUID;                       //! EncKey GUID
    SCP_KEY_DATA TweakKey;              //! AES Tweak Key
    SCP_KEY_DATA DataKey;             //! AES Data Key
};

/// <summary>
/// Represents a slot that contains encryption key
/// GUID and 4-byte padding
/// </summary>
struct SCP_GUID_SLOT
{
    GUID EncryptionKeyGUID;             //! Key associated w/ XVD
    uint32_t Padding;                   //! Padding
};
#pragma pack(pop)

