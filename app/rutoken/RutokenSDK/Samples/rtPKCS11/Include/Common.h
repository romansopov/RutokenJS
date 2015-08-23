/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Данный файл содержит объявление констант для работы с Рутокен при      *
* помощи библиотеки PKCS#11 на языке C                                   *
*************************************************************************/

#ifndef Common_H
#define Common_H

/************************************************************************
* Включение файлов:                                                     *
*  - stdio.h - для доступа к библиотеке стандартного ввода/вывода       *
*  - Windows.h - для доступа к функциям Win32API                        *
*  - WinCrypt.h - для доступа к функциям CryptoAPI                      *
*  - process.h - для доступа к функциям управления потоками и процессами*
*  - time.h - для доступа к функциям для работы со временем             *
*  - win2nix.h - для переопределения функций Windows для *nix-платформ  *
*  - wintypes.h - для переопределения типов данных Windows для          *
*    *nix-платформ                                                      *
*  - rtPKCS11.h - для доступа к функциям PKCS#11                        *
************************************************************************/
#ifdef _WIN32
	#include <stdio.h>
	#include <Windows.h>
	#include <WinCrypt.h>
	#include <process.h>
	#include <time.h>
#endif

#include "wintypes.h"
#include <rtpkcs11.h>
#include <win2nix.h>

/************************************************************************
* Макросы                                                               *
************************************************************************/
/* Имя библиотеки PKCS#11 */
#ifdef _WIN32
/* Библиотека для Рутокен S и Рутокен ЭЦП, поддерживает только алгоритмы RSA */
	#define PKCS11_LIBRARY_NAME         "rtPKCS11.dll" 
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11ECP_LIBRARY_NAME      "rtPKCS11ECP.dll"
#endif 
#ifdef __unix__
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11_LIBRARY_NAME         "librtpkcs11ecp.so"
	#define PKCS11ECP_LIBRARY_NAME      "librtpkcs11ecp.so"
#endif 	
#ifdef __APPLE__
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11_LIBRARY_NAME         "librtpkcs11ecp.dylib"
	#define PKCS11ECP_LIBRARY_NAME      "librtpkcs11ecp.dylib"
#endif 	

#ifndef TOKEN_TYPE_RUTOKEN
	#define TOKEN_TYPE_RUTOKEN 0x3 
#endif

#ifdef _WIN32
	#define HAVEMSCRYPTOAPI
#endif 

/* Вычисление размера массива */
#define arraysize(a)                (sizeof(a)/sizeof(a[0]))

/* Предопределенная константа RSA */
#define RSAENH_MAGIC_RSA1           0x31415352

/* Размер симметричного ключа ГОСТ 28147-89 в байтах */
#define GOST_28147_KEY_SIZE         0x20

/* Максимальное количество попыток ввода PIN-кода для Администратора */
#define MAX_ADMIN_RETRY_COUNT       10

/* Максимальное количество попыток доступа для Пользователя */
#define MAX_USER_RETRY_COUNT        10      

/************************************************************************
* Вспомогательные переменные                                            *
************************************************************************/
CK_BBOOL    bTrue                   = CK_TRUE;
CK_BBOOL    bFalse                  = CK_FALSE;

/* Длина модуля ключа RSA в битах */
CK_ULONG    ulRSAModBits            = 512;  

/* Набор параметров КриптоПро A алгоритма ГОСТ 28147-89 */
CK_BYTE     GOST28147_params_oid[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };

/* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2001 */
CK_BYTE     GOST3410_params_oid[]  = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };

/* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-1994 */
CK_BYTE     GOST3411_params_oid[]  = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };

/************************************************************************
* PIN-коды Рутокен                                                      *
************************************************************************/
/* DEMO PIN-код Пользователя Рутокен */
static CK_UTF8CHAR      USER_PIN[]      = {'1', '2', '3', '4', '5', '6', '7', '8'};

/* Новый DEMO PIN-код Пользователя Рутокен */
static CK_UTF8CHAR      NEW_USER_PIN[]  = {'5', '5', '5', '5', '5', '5', '5', '5'};

/* Неправильный DEMO PIN-код Пользователя Рутокен */
static CK_UTF8CHAR      WRONG_USER_PIN[]= {'0', '0', '0', '0', '0', '0', '0', '0'};

/* DEMO PIN-код Администратора Рутокен */
static CK_UTF8CHAR      SO_PIN[]        = {'8', '7', '6', '5', '4', '3', '2', '1'};

/************************************************************************
* Описание типов объектов                                               *
************************************************************************/
CK_OBJECT_CLASS     ocPubKey        = CKO_PUBLIC_KEY;
CK_OBJECT_CLASS     ocPrivKey       = CKO_PRIVATE_KEY;      
CK_OBJECT_CLASS     ocSeckey        = CKO_SECRET_KEY;
CK_OBJECT_CLASS     ocCert	        = CKO_CERTIFICATE;

/************************************************************************
* Описание типов ключей                                                 *
************************************************************************/
CK_KEY_TYPE         ktRSA               = CKK_RSA;
CK_KEY_TYPE         ktGOST28147_89      = CKK_GOST28147;
CK_KEY_TYPE         ktGOST34_10_2001    = CKK_GOSTR3410;

/************************************************************************
* Описание меток объектов                                               *
************************************************************************/
/* DEMO-метка открытого ключа RSA */
static CK_UTF8CHAR      PubLabelRSA[]       = {"Sample RSA Public Key (Aktiv Co.)"};

/* DEMO-метка закрытого ключа RSA */
static CK_UTF8CHAR      PrivLabelRSA[]      = {"Sample RSA Private Key (Aktiv Co.)"};

/* DEMO ID пары ключей RSA */
static CK_BYTE          KeyPairIDRSA[]      = {"RSA sample keypair ID (Aktiv Co.)"};

/* DEMO-метка  открытого ключа #1 ГОСТ Р 34.10-2001 */
static CK_UTF8CHAR      PubLabelGOST1[]     = {"Sample GOST R 34.10-2001 Public Key 1 (Aktiv Co.)"};

/* DEMO-метка  закрытого ключа #1 ГОСТ Р 34.10-2001 */
static CK_UTF8CHAR      PrivLabelGOST1[]    = {"Sample GOST R 34.10-2001 Private Key 1 (Aktiv Co.)"};

/* DEMO ID пары ключей #1 ГОСТ Р 34.10-2001 */
static CK_BYTE          KeyPairIDGOST1[]    = {"GOST R 34.10-2001 sample keypair 1 ID (Aktiv Co.)"};

/* DEMO-метка открытого ключа #2 ГОСТ Р 34.10-2001 */
static CK_UTF8CHAR      PubLabelGOST2[]     = {"Sample GOST R 34.10-2001 Public Key 2 (Aktiv Co.)"};

/* DEMO-метка закрытого ключа #2 ГОСТ Р 34.10-2001 */
static CK_UTF8CHAR      PrivLabelGOST2[]    = {"Sample GOST R 34.10-2001 Private Key 2 (Aktiv Co.)"};

/* DEMO ID пары ключей # 2 ГОСТ Р 34.10-2001 */
static CK_BYTE          KeyPairIDGOST2[]    = {"GOST R 34.10-2001 sample keypair 2 ID (Aktiv Co.)"};

/* DEMO-метка симметричного ключа ГОСТ 28147-89 */
static CK_UTF8CHAR      SecLabelGOST[]      = {"Sample GOST 28147-89 Secret Key (Aktiv Co.)"};

/* DEMO ID симметричного ключа ГОСТ 28147-89 */
static CK_BYTE          SecKeyIDGOST[]      = {"GOST 28147-89 Secret Key ID (Aktiv Co.)"};

/* DEMO-метка общего выработанного ключа */
static CK_UTF8CHAR      DerivedLabelGOST[]  = {"Derived GOST 28147-89 key"};

/* DEMO-метка для маскируемого ключа */
static CK_UTF8CHAR      WrapLabelGOST[]     = {"GOST 28147-89 key to wrap"};

/* DEMO-метка для демаскированного ключа */
static CK_UTF8CHAR      UnWrapLabelGOST[]   = {"Unwrapped GOST 28147-89 key"};

/************************************************************************
* Описание меток токена                                                 *
************************************************************************/
/* DEMO метка Rutoken ("длинная") */
static CK_CHAR TOKEN_LONG_LABEL[]   = {"!!!Sample Rutoken Long-long-long-long-long label!!!"};

/* DEMO метка Rutoken ("обычная") */
static CK_CHAR TOKEN_STD_LABEL[]    = {"!!!Sample Rutoken label!!!"};

/* DEMO метка Rutoken */
static CK_CHAR TOKEN_LABEL[]        = { 'M', 'y', ' ', 'R', 'u', 't', 'o', 'k',
                                        'e', 'n', ' ', ' ', ' ', ' ', ' ', ' ',
                                        ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                        ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };

/*************************************************************************
* Механизмы PKCS#11                                                      *
*************************************************************************/
/*  Механизм генерации ключевой пары RSA */
CK_MECHANISM    ckmRSAKeyGenMech            = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

/* Механизм шифрования/расшифрования, подписи/проверки подписи по алгоритму RSA */
CK_MECHANISM    ckmEncDecMech               = {CKM_RSA_PKCS, NULL_PTR, 0};

/*  Механизм генерации ключевой пары ГОСТ Р 34.10-2001 */
CK_MECHANISM    ckmGOST34_10_2001KeyGenMech = {CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0};

/*  Механизм подписи/проверки подписи по алгоритму ГОСТ Р 34.10-2001 */
CK_MECHANISM    ckmGOST_34_10_2001SigVerMech= {CKM_GOSTR3410, NULL_PTR, 0};

/*  Механизм подписи/проверки подписи по алгоритму ГОСТ Р 34.10-2001 с хешированием по алгоритму ГОСТ Р 34.11-94*/
CK_MECHANISM    ckmGOST_34_10_2001_with_34_11 = {CKM_GOSTR3410_WITH_GOSTR3411, GOST3411_params_oid, sizeof(GOST3411_params_oid)};

/*  Механизм генерации симметричного ключа по алгоритму ГОСТ 28147-89 */
CK_MECHANISM    ckmGOST28147_89_KeyGenMech  = {CKM_GOST28147_KEY_GEN, NULL_PTR, 0};

/* Механизм шифрования/расшифрования по алгоритму ГОСТ 28147-89 */
CK_MECHANISM    ckmEncDecGOSTMech           = {CKM_GOST28147_ECB, NULL_PTR, 0};
CK_MECHANISM    ckmEncDecGOSTMech2          = {CKM_GOST28147, NULL_PTR, 0 };

/*  Механизм хеширования SHA-1 */
CK_MECHANISM    ckmSHA1Mech                 = {CKM_SHA_1, NULL_PTR, 0};

/*  Механизм хеширования ГОСТ Р 34.11-94 */
CK_MECHANISM    ckmGOST34_11_94Mech         = {CKM_GOSTR3411, NULL_PTR, 0};

/* Механизм для маскирования/демаскирования ключа */
CK_MECHANISM    ckmWrapMech                 = {CKM_GOST28147_KEY_WRAP, NULL_PTR, 0};

/* Механизм выработки общего ключа */
CK_MECHANISM    ckmDerivationMech           = {CKM_GOSTR3410_DERIVE, NULL_PTR, 0}; 

/* Параметры для выработки общего ключа */
CK_GOSTR3410_DERIVE_PARAMS ckDeriveParams   = {CKD_CPDIVERSIFY_KDF, NULL_PTR, 0, NULL_PTR, 0};

#endif //PKCS11_COMMON_H
