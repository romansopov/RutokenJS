/*******************************************************************
* Copyright (C) Aktiv Co. 2003-2014                                *
* rtpkcs11t.h                                                      *
* Файл, включающий все символы для работы с библиотекой PKCS#11,   *
* а также расширения для Rutoken.                                  *
********************************************************************/

#ifndef __RTPKCS11T_H__
#define __RTPKCS11T_H__

#define NSSCK_VENDOR_PKCS11_RU_TEAM     (CKR_VENDOR_DEFINED | 0x54321000)
#define CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

/* GOST KEY TYPES */
#define CKK_GOSTR3410                   0x00000030
#define CKK_GOSTR3411                   0x00000031
#define CKK_GOST28147                   0x00000032
#define CKK_GOSTR3410_512               (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

/* GOST OBJECT ATTRIBUTES */
#define CKA_GOSTR3410_PARAMS            0x00000250
#define CKA_GOSTR3411_PARAMS            0x00000251
#define CKA_GOST28147_PARAMS            0x00000252

/* Extended attributes for GOST private and secret keys (for "PINPad 2" only) */
/* Операция подписи или шифрования/расшифрования требует ввода PIN - тип CK_BBOOL */
#define CKA_VENDOR_KEY_PIN_ENTER        (CKA_VENDOR_DEFINED | 0x2000)
/* Операция подписи или шифрования/расшифрования требует подтверждения - тип CK_BBOOL */
#define CKA_VENDOR_KEY_CONFIRM_OP       (CKA_VENDOR_DEFINED | 0x2001)

#define CKA_NAME_HASH_ALGORITHM         0x0000008C
#define CKA_COPYABLE                    0x00000171

/* GOST MECHANISMS */
#define CKM_GOSTR3410_KEY_PAIR_GEN              0x00001200
#define CKM_GOSTR3410                           0x00001201
#define CKM_GOSTR3410_WITH_GOSTR3411            0x00001202
#define CKM_GOSTR3410_KEY_WRAP                  0x00001203
#define CKM_GOSTR3410_DERIVE                    0x00001204
#define CKM_GOSTR3410_512_KEY_PAIR_GEN          (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#define CKM_GOSTR3410_512                       (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#define CKM_GOSTR3410_12_DERIVE                 (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#define CKM_GOSTR3410_WITH_GOSTR3411_12_256     (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#define CKM_GOSTR3410_WITH_GOSTR3411_12_512     (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#define CKM_GOSTR3411                           0x00001210
#define CKM_GOSTR3411_HMAC                      0x00001211
#define CKM_GOSTR3411_12_256                    (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#define CKM_GOSTR3411_12_512                    (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#define CKM_GOSTR3411_12_256_HMAC               (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#define CKM_GOSTR3411_12_512_HMAC               (CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#define CKM_GOST28147_KEY_GEN                   0x00001220
#define CKM_GOST28147_ECB                       0x00001221
#define CKM_GOST28147                           0x00001222
#define CKM_GOST28147_MAC                       0x00001223
#define CKM_GOST28147_KEY_WRAP                  0x00001224

#define CKD_CPDIVERSIFY_KDF             0x00000009
#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411  0x00000002

typedef struct CK_GOSTR3410_KEY_WRAP_PARAMS {
  CK_BYTE_PTR pWrapOID;
  CK_ULONG ulWrapOIDLen;
  CK_BYTE_PTR pUKM;
  CK_ULONG ulUKMLen;
  CK_OBJECT_HANDLE hKey;
} CK_GOSTR3410_KEY_WRAP_PARAMS;

typedef CK_GOSTR3410_KEY_WRAP_PARAMS CK_PTR CK_GOSTR3410_KEY_WRAP_PARAMS_PTR;

typedef struct CK_GOSTR3410_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pUKM;
  CK_ULONG ulUKMLen;
} CK_GOSTR3410_DERIVE_PARAMS;

typedef CK_GOSTR3410_DERIVE_PARAMS CK_PTR CK_GOSTR3410_DERIVE_PARAMS_PTR;

/* Do not attach signed data to PKCS#7 signature */
#define PKCS7_DETACHED_SIGNATURE 0x01

/* CK_FUNCTION_LIST_EXTENDED is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki extended functions */
typedef struct CK_FUNCTION_LIST_EXTENDED CK_FUNCTION_LIST_EXTENDED;

typedef CK_FUNCTION_LIST_EXTENDED CK_PTR CK_FUNCTION_LIST_EXTENDED_PTR;

typedef CK_FUNCTION_LIST_EXTENDED_PTR CK_PTR CK_FUNCTION_LIST_EXTENDED_PTR_PTR;

/* Data structure use in C_EX_InitToken - extended function */
/* for all token reformat (C_InitToken will format only PKCS#11) */
/*
 * ulSizeofThisStructure [in] - init this field by size of this
 *                              structure. For example -
 *         st.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM)
 *
 * UseRepairMode [in] == 0: format procedure requires authentication
 *                          as administrator
 *                    != 0: format procedure executes without
 *                          authentication as administrator
 *
 * pNewAdminPin [in] - pointer to byte array with new administrator
 *                     PIN
 *
 * ulNewAdminPinLen [in] - length of new administrator PIN:
 *                minimum bMinAdminPinLength bytes, maximum 32 bytes.
 *
 * pNewUserPin [in] - pointer to byte array with new user PIN
 *
 * ulNewUserPinLen [in] - length of new user PIN:
 *                 minimum bMinUserPinLength bytes, maximum 32 bytes.
 *
 * ChangeUserPINPolicy [in] - (flags) policy of change user PIN.
 *        Values:
 *        1) if set TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN (0x1) -
 *           administrator can change user PIN
 *        2) if set TOKEN_FLAGS_USER_CHANGE_USER_PIN (0x2) - user can
 *           change user PIN
 *        3) if set 2 flags: TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN and
 *           TOKEN_FLAGS_USER_CHANGE_USER_PIN (0x3) - administrator
 *           and user can change user PIN
 *        4) in another cases - error
 *
 * ulMinAdminPinLen [in] - minimal size of administrator PIN
 *                         minimum 6 byte, maximum 32 bytes.
 *
 * ulMinUserPinLen [in] - minimal size of user PIN
 *                        minimum 6 byte, maximum 32 bytes.
 *
 * ulMaxAdminRetryCount [in] - minimum 3, maximum 10
 * ulMaxUserRetryCount [in] - minimum 1, maximum 10
 *
 * pTokenLabel [in] - pointer to byte array with new token symbol
 *                    name, if pTokenLabel == NULL - token symbol
 *                    name will not set
 *
 * ulLabelLen [in] - length of new token symbol name
 */
typedef struct CK_RUTOKEN_INIT_PARAM {
  CK_ULONG    ulSizeofThisStructure;
  CK_ULONG    UseRepairMode;
  CK_BYTE_PTR pNewAdminPin;
  CK_ULONG    ulNewAdminPinLen;
  CK_BYTE_PTR pNewUserPin;
  CK_ULONG    ulNewUserPinLen;
  /* Correct values (see description):
   * TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN
   * TOKEN_FLAGS_USER_CHANGE_USER_PIN
   * TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN
   */
  CK_FLAGS    ChangeUserPINPolicy; /* see below */
  CK_ULONG    ulMinAdminPinLen;
  CK_ULONG    ulMinUserPinLen;
  CK_ULONG    ulMaxAdminRetryCount;
  CK_ULONG    ulMaxUserRetryCount;
  CK_BYTE_PTR pTokenLabel;
  CK_ULONG    ulLabelLen;
} CK_RUTOKEN_INIT_PARAM;

typedef CK_RUTOKEN_INIT_PARAM CK_PTR CK_RUTOKEN_INIT_PARAM_PTR;

/* CK_TOKEN_INFO_EXTENDED provides extended information about a
 * token */
typedef struct CK_TOKEN_INFO_EXTENDED {
  /* init this field by size of this structure
   * [in] - size of input structure
   * [out] - return size of filled structure
   */
  CK_ULONG ulSizeofThisStructure;
  /* type of token: */
  CK_ULONG ulTokenType;       /* see below */
  /* exchange protocol number */
  CK_ULONG ulProtocolNumber;
  /* microcode number */
  CK_ULONG ulMicrocodeNumber;
  /* order number */
  CK_ULONG ulOrderNumber;
  /* information flags */
  /* TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN - administrator can change user PIN
   * TOKEN_FLAGS_USER_CHANGE_USER_PIN  - user can change user PIN
   * TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT - administrator PIN not default
   * TOKEN_FLAGS_USER_PIN_NOT_DEFAULT  - user PIN not default
   * TOKEN_FLAGS_SUPPORT_FKN           - token support CryptoPro FKN
   */
  CK_FLAGS flags;                 /* see below */
  /* maximum and minimum PIN length */
  CK_ULONG ulMaxAdminPinLen;
  CK_ULONG ulMinAdminPinLen;
  CK_ULONG ulMaxUserPinLen;
  CK_ULONG ulMinUserPinLen;
  /* max count of unsuccessful login attempts */
  CK_ULONG ulMaxAdminRetryCount;
  /* count of unsuccessful attempts left (for administrator PIN)
   * if field equal 0 - that means that PIN is blocked */
  CK_ULONG ulAdminRetryCountLeft;
  /* min counts of unsuccessful login attempts */
  CK_ULONG ulMaxUserRetryCount;
  /* count of unsuccessful attempts left (for user PIN)
   * if field equal 0 - that means that PIN is blocked */
  CK_ULONG ulUserRetryCountLeft;
  /* token serial number in Big Endian format */
  CK_BYTE  serialNumber[8];
  /* size of all memory */
  CK_ULONG ulTotalMemory;         /* in bytes */
  /* size of free memory */
  CK_ULONG ulFreeMemory;          /* in bytes */
  /* atr of the token */
  CK_BYTE  ATR[64];
  /* size of atr */
  CK_ULONG ulATRLen;
  /* class of token */
  CK_ULONG ulTokenClass;          /* see below */
  /* Battery Voltage */
  CK_ULONG ulBatteryVoltage;      /* microvolts */
  /* Body color of the token */
  CK_ULONG ulBodyColor;           /* see below */
} CK_TOKEN_INFO_EXTENDED;

typedef CK_TOKEN_INFO_EXTENDED CK_PTR CK_TOKEN_INFO_EXTENDED_PTR;

/* Token types (field "ulTokenType") */
#define TOKEN_TYPE_UNKNOWN                0xFF
#define TOKEN_TYPE_RUTOKEN_ECP            0x01
#define TOKEN_TYPE_RUTOKEN_LITE           0x02
#define TOKEN_TYPE_RUTOKEN                0x03
#define TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY  0x04
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_USB    0x09
#define TOKEN_TYPE_RUTOKEN_KAZTOKEN       0x11
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_BT     0x69
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_UART   0xA9
#define TOKEN_TYPE_RUTOKEN_WEB            0x23
#define TOKEN_TYPE_RUTOKEN_SC_JC          0x41
#define TOKEN_TYPE_RUTOKEN_LITE_SC_JC     0x42
#define TOKEN_TYPE_RUTOKEN_KAZTOKEN_SC_JC 0x51
#define TOKEN_TYPE_RUTOKEN_ECP_SD         0x81
#define TOKEN_TYPE_RUTOKEN_LITE_SD        0x82
#define TOKEN_TYPE_RUTOKEN_KAZTOKEN_SD    0x91

/* Token flags (field "flags" from CK_TOKEN_INFO_EXTENDED +
 * field "ChangeUserPINPolicy" from CK_RUTOKEN_INIT_PARAM) */
/* TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN - if it is set, that
 * means that administrator (SO) can change user PIN
 */
#define TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN 0x00000001

/* TOKEN_FLAGS_USER_CHANGE_USER_PIN - if it is set, that
 * means that user can change user PIN
 */
#define TOKEN_FLAGS_USER_CHANGE_USER_PIN  0x00000002

/* TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT - if it is set, that
 * means that current administrator (SO) PIN is not default
 */
#define TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT 0x00000004

/* TOKEN_FLAGS_USER_PIN_NOT_DEFAULT - if it is set, that
 * means that current user PIN not default
 */
#define TOKEN_FLAGS_USER_PIN_NOT_DEFAULT  0x00000008

/* TOKEN_FLAGS_SUPPORT_FKN - if it is set, that
 * means that token supports CryptoPro FKN
 */
#define TOKEN_FLAGS_SUPPORT_FKN           0x00000010

/* TOKEN_FLAGS_SUPPORT_SM - if it is set, that
 * means that token supports Secure Messaging
 */
#define TOKEN_FLAGS_SUPPORT_SM            0x00000040

/* class of token */
#define TOKEN_CLASS_UNKNOWN             0xFFFFFFFF
#define TOKEN_CLASS_S                   0x00
#define TOKEN_CLASS_ECP                 0x01
#define TOKEN_CLASS_LITE                0x02
#define TOKEN_CLASS_WEB                 0x03
#define TOKEN_CLASS_PINPAD              0x04
#define TOKEN_CLASS_ECPDUAL             0x09
#define TOKEN_CLASS_KAZTOKEN            0x11

/* Body color of the token */
#define TOKEN_BODY_COLOR_UNKNOWN        0
#define TOKEN_BODY_COLOR_WHITE          1
#define TOKEN_BODY_COLOR_BLACK          2

/* Расширенные коды ошибок */
#define CKR_CORRUPTED_MAPFILE           (CKR_VENDOR_DEFINED+1)
#define CKR_WRONG_VERSION_FIELD         (CKR_VENDOR_DEFINED+2)
#define CKR_WRONG_PKCS1_ENCODING        (CKR_VENDOR_DEFINED+3)
#define CKR_RTPKCS11_DATA_CORRUPTED     (CKR_VENDOR_DEFINED+4)
#define CKR_RTPKCS11_RSF_DATA_CORRUPTED (CKR_VENDOR_DEFINED+5)

/* Неверный формат данных, переданных на подпись в PINPad,
 * или пользователь отказался от подписи данных */
#define CKR_PINPAD_DATA_INCORRECT       (CKR_VENDOR_DEFINED+0x6FB1)
/* Размер данных, переданных на подпись в PINPad, больше допустимого */
#define CKR_PINPAD_WRONG_DATALEN        (CKR_VENDOR_DEFINED+0x6FB6)

/* Rutoken TM 2 */
typedef CK_ULONG CK_VOLUME_ID_EXTENDED;
typedef CK_ULONG CK_ACCESS_MODE_EXTENDED;
typedef CK_ULONG CK_OWNER_EXTENDED;

#define CKF_ENCRYPTION                  0x01000000

#define ACCESS_MODE_HIDDEN              0x00
#define ACCESS_MODE_RO                  0x01
#define ACCESS_MODE_RW                  0x03
#define ACCESS_MODE_CD                  0x05

typedef struct CK_VOLUME_INFO_EXTENDED
{
  CK_VOLUME_ID_EXTENDED   idVolume;     /* Идентификатор раздела, от 1 до 9 */
  CK_ULONG                ulVolumeSize; /* Размер раздела в Мб, не больше общего объема носителя */
  CK_ACCESS_MODE_EXTENDED accessMode;   /* Флаги доступа */
  CK_OWNER_EXTENDED       volumeOwner;  /* Владелец раздела (кто может менять флаги доступа к разделу) */
  CK_FLAGS                flags;        /* Остальные флаги (пока только шифрование) */
} CK_VOLUME_INFO_EXTENDED;

typedef struct CK_VOLUME_FORMAT_INFO_EXTENDED
{
  CK_ULONG                ulVolumeSize;
  CK_ACCESS_MODE_EXTENDED accessMode;
  CK_OWNER_EXTENDED       volumeOwner;
  CK_FLAGS                flags;
} CK_VOLUME_FORMAT_INFO_EXTENDED;

typedef CK_VOLUME_INFO_EXTENDED CK_PTR CK_VOLUME_INFO_EXTENDED_PTR;
typedef CK_VOLUME_FORMAT_INFO_EXTENDED CK_PTR CK_VOLUME_FORMAT_INFO_EXTENDED_PTR;

/* Rutoken S vendor defined constants */

/* Механизм генерации ключей ГОСТ */
#define CKM_GOST_KEY_GEN        (CKM_VENDOR_DEFINED + 1)

/* Механизм шифрования по алгоритму ГОСТ */
#define CKM_GOST                (CKM_VENDOR_DEFINED + 2)

/* CK_KEY_TYPE объекта CKO_SECRET_KEY*/
#define CKK_GOST                (CKK_VENDOR_DEFINED + 1)

/* Атрибут ключа ГОСТ - его опции */
#define CKA_GOST_KEY_OPTIONS    (CKA_VENDOR_DEFINED + 1)

/* Атрибут ключа ГОСТ - его флаги */
#define CKA_GOST_KEY_FLAGS      (CKA_VENDOR_DEFINED + 2)

/* Возможные опции ключа ГОСТ */
#define CKO_GOST_KEY_PZ         0x00    /* Простая замена */
#define CKO_GOST_KEY_GAMM       0x01    /* Гаммирование (по умолчанию) */
#define CKO_GOST_KEY_GAMMOS     0x02    /* Гаммирование с обратной связью */

/* Возможные флаги ключа ГОСТ */
#define CKF_GOST_KEY_CLOSED     0x00    /* Закрытый ключ (по умолчанию) */
#define CKF_GOST_KEY_OPENLEN    0x02    /* Ключ с открытой длиной */

#endif /* __RTPKCS11T_H__ */

