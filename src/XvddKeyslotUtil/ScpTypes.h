#pragma once

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
};

/// <summary>
/// Data layout for CIK exporting
/// </summary>
struct SCP_LICENSE {
    GUID KeyGUID;                       //! EncKey GUID
    SCP_KEY_DATA FirstKey;              //! AES Tweak Key
    SCP_KEY_DATA SecondKey;             //! AES Data Key
};

/// <summary>
/// Represents a slot that contains encryption key
/// GUID and 4-byte padding. We use this padding to
/// store the associated keyslot indexes.
/// </summary>
struct SCP_GUID_SLOT_CONTENT
{
    GUID EncryptionKeyGUID;             //! Key associated w/ XVD
    uint16_t FirstKeyId;                //! Padding
    uint16_t SecondKeyId;               //! Padding
};

struct SCP_GUID_SLOT {
    SCP_GUID_SLOT_CONTENT Data[64];
};
#pragma pack(pop)

