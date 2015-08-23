/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд выработки общего ключа, шифрования одного ключа   *
* другим:                                                                *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - выработка общего ключа на первой стороне;                           *
*  - маскирование ключа на выработанном общем ключе;                     *
*  - выработка общего ключа на второй стороне;                           *
*  - демаскирование ключа на выработанном общем ключе;                   *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Пример использует объекты, созданные в памяти Рутокен примером         *
* CreateGOST34.10-2001                                                   *
*************************************************************************/

#include "Common.h"

/* Шаблон для поиска закрытого ключа отправителя */
CK_ATTRIBUTE attrSenderPrivateKey[] =
{
	{ CKA_ID, KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey) }
};

/* Шаблон для поиска закрытого ключа получателя */
CK_ATTRIBUTE attrRecipientPrivateKey[] =
{
	{ CKA_ID, KeyPairIDGOST2, sizeof(KeyPairIDGOST2) - 1},
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey) }
};

/* Шаблон для поиска открытого ключа отправителя */
CK_ATTRIBUTE attrSenderPublicKey[] =
{
	{ CKA_ID, KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey) }
};

/* Шаблон для поиска открытого ключа получателя */
CK_ATTRIBUTE attrRecipientPublicKey[] =
{
	{ CKA_ID, KeyPairIDGOST2, sizeof(KeyPairIDGOST2) - 1},
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey) }
};

/* Шаблон для создания общего выработанного ключа */
CK_ATTRIBUTE attrGOST28147_89DerivedKey[] =
{
	{ CKA_CLASS, &ocSeckey, sizeof(ocSeckey)},                              // Объект секретного ключа ГОСТ 28147-89
	{ CKA_LABEL, &DerivedLabelGOST, sizeof(DerivedLabelGOST) - 1},          // Метка ключа
	{ CKA_KEY_TYPE, &ktGOST28147_89, sizeof(ktGOST28147_89)},               // Тип ключа
	{ CKA_TOKEN, &bFalse, sizeof(bFalse)},                                  // Ключ является объектом сессии
	{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue)},                               // Ключ может быть изменен после создания
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                                // Ключ доступен без авторизации на токене
	{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)},                              // Ключ может быть извлечен из токена и зашифрован
	{ CKA_SENSITIVE, &bFalse, sizeof(bFalse)}                               // Ключ не может быть извлечен в открытом виде из токена
};

/* Шаблон маскируемого ключа */
CK_ATTRIBUTE attrGOST28147_89KeyToWrap[] =
{
	{ CKA_CLASS, &ocSeckey, sizeof(ocSeckey)},                      // Объект секретного ключа ГОСТ 28147-89
	{ CKA_LABEL, &WrapLabelGOST, sizeof(WrapLabelGOST) - 1 },       // Метка ключа
	{ CKA_KEY_TYPE, &ktGOST28147_89, sizeof(ktGOST28147_89)},       // Тип ключа
	{ CKA_TOKEN, &bFalse, sizeof(bFalse)},                          // Ключ является объектом сессии
	{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue)},                       // Ключ может быть изменен после создания
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Ключ доступен без авторизации на токене
	{ CKA_VALUE, NULL_PTR, 0},                                      // Значение ключа
	{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)},                      // Ключ может быть извлечен из токена и зашифрован
	{ CKA_SENSITIVE, &bFalse, sizeof(bFalse)}                       // Ключ не может быть извлечен в открытом виде из токена
};

/* Шаблон демаскированного ключа */
CK_ATTRIBUTE attrGOST28147_89UnwrappedKey[] =
{
	{ CKA_CLASS, &ocSeckey, sizeof(ocSeckey)},                              // Объект секретного ключа ГОСТ 28147-89
	{ CKA_LABEL, &UnWrapLabelGOST, sizeof(UnWrapLabelGOST) - 1},            // Метка ключа
	{ CKA_KEY_TYPE, &ktGOST28147_89, sizeof(ktGOST28147_89)},               // Тип ключа
	{ CKA_TOKEN, &bFalse, sizeof(bFalse)},                                  // Ключ является объектом сессии
	{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue)},                               // Ключ может быть изменен после создания
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                                // Ключ доступен без авторизации на токене
	{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)},                              // Ключ может быть извлечен из токена и зашифрован
	{ CKA_SENSITIVE, &bFalse, sizeof(bFalse)}                               // Ключ не может быть извлечен в открытом виде из токена
};

/************************************************************************
* Генерация случайной последовательности заданной длины                 *
************************************************************************/
void GenerateRandomData(IN DWORD dwDataSize,       // Размер буфера со случайными данными, в байтах
                        OUT PBYTE* pbtData)        // Указатель на буфер со сгенерированными случайными данными

{
	DWORD i = 0;                                   // Вспомогательная переменная-счетчик в циклах
	srand((unsigned)time(NULL));

	*pbtData = (BYTE*)malloc(dwDataSize * sizeof(BYTE));
	memset(*pbtData,
	       0,
	       (dwDataSize * sizeof(BYTE)));

	for (i = 0;
	     i < dwDataSize;
	     i++)
		(*pbtData)[i] = (BYTE)rand();
}

/************************************************************************
* Получить массив хэндлов объектов, соответствующих критериям поиска    *
************************************************************************/
BOOL FindObjects(IN CK_SESSION_HANDLE hSession,               // Хэндл открытой сессии
                 IN CK_FUNCTION_LIST_PTR pFunctionList,       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
                 IN CK_ATTRIBUTE_PTR pTemplate,               // Указатель на шаблон, в который помещены атрибуты для поиска
                 IN CK_ULONG ulCount,                         // Количество атрибутов в шаблоне поиска
                 OUT CK_OBJECT_HANDLE_PTR* pphObject,         // Указатель на массив хэндлов объектов, соответствующих критериям поиска
                 OUT CK_ULONG* pulObjectCount,                // Количество хэндлов в массиве
                 OUT CK_RV* prv                               // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
                 )
{
	CK_RV rvTemp = CKR_OK;                                    // Вспомогательная переменная для хранения кода возврата
	*pulObjectCount = 0;
	*pphObject = NULL_PTR;

	while (TRUE)
	{
		/**********************************************************************
		* Инициализировать операцию поиска                                    *
		**********************************************************************/
		printf(" C_FindObjectsInit");
		*prv = pFunctionList->C_FindObjectsInit(hSession,
		                                        pTemplate,
		                                        ulCount);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Найти все объекты, соответствующие критериям поиска                 *
		**********************************************************************/
		printf(" C_FindObjects");

		// Считаем, что максимальное количество объектов не превышает 100
		*pphObject = (CK_OBJECT_HANDLE*)malloc(100 * sizeof(CK_OBJECT_HANDLE));
		memset(*pphObject,
		       0,
		       (100 * sizeof(CK_OBJECT_HANDLE)));

		*prv = pFunctionList->C_FindObjects(hSession,
		                                    *pphObject,
		                                    100,
		                                    pulObjectCount);
		if (*prv != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		break;
	}

	/**********************************************************************
	* Деинициализировать операцию поиска                                  *
	**********************************************************************/
	printf(" C_FindObjectsFinal");
	rvTemp = pFunctionList->C_FindObjectsFinal(hSession);
	if (rvTemp != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	if (*prv == CKR_OK)
		printf("Search has been completed.\n"
		       "Objects found: %d \n",
		       (int)*pulObjectCount);
	else
	{
		printf("Search failed!\n");
		if (pphObject)
		{
			free(pphObject);
			*pphObject = NULL_PTR;
			*pulObjectCount = 0;
		}
	}

	return *prv == CKR_OK;
}

/************************************************************************
* Получить значение атрибута CKA_VALUE у заданного объекта              *
************************************************************************/
BOOL GetObjectValue(IN CK_SESSION_HANDLE hSession,             // Хэндл открытой сессии
                    IN CK_FUNCTION_LIST_PTR pFunctionList,     // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
                    IN CK_OBJECT_HANDLE hObject,               // Хэндл объекта
                    OUT CK_BYTE_PTR* pbtValue,                 // Указатель на буфер, содержащий полученное значение атрибута
                    OUT CK_ULONG* pulValueSize,                // Размер буфера для хранения полученного значения атрибута, в байтах
                    OUT CK_RV* prv                             // Код возврата
                    )
{
	CK_ATTRIBUTE attrValue = {CKA_VALUE, NULL_PTR, 0};          // Струтура данных типа CK_ATTRIBUTE для хранения значения атрибута CKA_VALUE

	while (TRUE)
	{
		/**********************************************************************
		* Получить размер буфера для хранения значения атрибута CKA_VALUE     *
		**********************************************************************/
		printf("  Getting object value size");
		*prv = pFunctionList->C_GetAttributeValue(hSession,
		                                          hObject,
		                                          &attrValue,
		                                          1);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Выделить необходимое количество памяти для значения атрибута        *
		**********************************************************************/
		attrValue.pValue = (CK_BYTE*)malloc(attrValue.ulValueLen);
		memset(attrValue.pValue,
		       0,
		       (attrValue.ulValueLen * sizeof(CK_BYTE)));

		/**********************************************************************
		* Получить значение атрибута CKA_VALUE                                *
		**********************************************************************/
		printf("  Getting object value");
		*prv = pFunctionList->C_GetAttributeValue(hSession,
		                                          hObject,
		                                          &attrValue,
		                                          1);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		*pulValueSize = attrValue.ulValueLen;
		*pbtValue = (CK_BYTE*)malloc(*pulValueSize);
		memset(*pbtValue,
		       0,
		       (*pulValueSize * sizeof(CK_BYTE)));
		memcpy(*pbtValue,
		       attrValue.pValue,
		       (*pulValueSize * sizeof(CK_BYTE)));
		break;
	}

	if (attrValue.pValue)
	{
		free(attrValue.pValue);
		attrValue.pValue = NULL_PTR;
		attrValue.ulValueLen = 0;
	}

	if (*prv == CKR_OK)
		printf(" Object value has been obtained.\n");
	else
		printf(" Cannot obtain object value!\n\n");
	return *prv == CKR_OK;
}

/**********************************************************************
* Выработать общий ключ ГОСТ 28147-89 для отправителя и получателя    *
**********************************************************************/
BOOL DeriveKey(IN CK_SESSION_HANDLE hSession,                            // Хэндл сессии
               IN CK_FUNCTION_LIST_PTR pFunctionList,                    // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
               IN CK_ATTRIBUTE_PTR pPrivateKeyFindTemplate,              // Указатель на шаблон для поиска закрытого ключа отправителя
               IN CK_ULONG ulPrivateKeyFindTemplateSize,                 // Количество атрибутов в шаблоне для поиска закрытого ключа отправителя
               IN CK_ATTRIBUTE_PTR pPublicKeyFindTemplate,               // Указатель на шаблон для поиска открытого ключа получателя
               IN CK_ULONG ulPublicKeyFindTemplateSize,                  // Количество атрибутов в шаблоне для поиска открытого ключа получателя
               OUT CK_OBJECT_HANDLE* phDerivedKey,                       // Хэндл выработанного общего ключа
               OUT CK_RV* prv                                            // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
               )
{
	CK_OBJECT_HANDLE_PTR ahPrivateKeys = NULL_PTR;          // Указатель на массив хэндлов закрытых ключей отправителя, соответствующих критериям поиска
	CK_ULONG ulPrivateKeysNumber = 0;                       // Количество хэндлов закрытых ключей отправителя в массиве

	CK_OBJECT_HANDLE_PTR ahPublicKeys = NULL_PTR;           // Указатель на массив хэндлов открытых ключей получателя, соответствующих критериям поиска
	CK_ULONG ulPublicKeysNumber = 0;                        // Количество хэндлов открытых ключей получателя в массиве

	CK_BYTE_PTR pbtDerivedKey = NULL_PTR;                   // Указатель на буфер, содержащий тело выработанного ключа
	CK_ULONG ulDerivedKeySize = 0;                          // Размер буфера, содержащего тело выработанного ключа, в байтах

	DWORD i = 0;                                            // Вспомогательная переменная-счетчик в циклах

	printf("\nDeriving key...\n");
	while (TRUE)
	{
		/************************************************************************
		* Получить массив хэндлов закрытых ключей отправителя                   *
		************************************************************************/
		printf(" Getting sender key...\n");
		FindObjects(hSession,
		            pFunctionList,
		            pPrivateKeyFindTemplate,
		            ulPrivateKeyFindTemplateSize,
		            &ahPrivateKeys,
		            &ulPrivateKeysNumber,
		            prv);
		if (*prv != CKR_OK)
			break;
		if (ulPrivateKeysNumber == 0)
		{
			printf("No private key found!\n");
			break;
		}

		/************************************************************************
		* Получить массив хэндлов открытых ключей получателя                    *
		************************************************************************/
		printf(" Getting public key...\n");
		FindObjects(hSession,
		            pFunctionList,
		            pPublicKeyFindTemplate,
		            ulPublicKeyFindTemplateSize,
		            &ahPublicKeys,
		            &ulPublicKeysNumber,
		            prv);
		if (*prv != CKR_OK)
			break;
		if (ulPublicKeysNumber == 0)
		{
			printf("No public key found!\n");
			break;
		}

		/************************************************************************
		* Поместить в структуру типа CK_GOSTR3410_DERIVE_PARAMS                 *
		* открытый ключ получателя                                              *
		************************************************************************/
		printf(" Getting public key value...\n");
		GetObjectValue(hSession,
		               pFunctionList,
		               ahPublicKeys[0],
		               &ckDeriveParams.pPublicData,
		               &ckDeriveParams.ulPublicDataLen,
		               prv);
		if (*prv != CKR_OK)
			break;

		/************************************************************************
		* Поместить в структуру типа CK_MECHANISM параметры, необходимые        *
		* для выработки общего ключа                                            *
		************************************************************************/
		ckmDerivationMech.pParameter = &ckDeriveParams;
		ckmDerivationMech.ulParameterLen = sizeof(ckDeriveParams);

		/************************************************************************
		* Выработать общий ключ ГОСТ 28147-89 на основании закрытого            *
		* ключа отправителя и открытого ключа получателя                        *
		************************************************************************/
		printf(" C_DeriveKey");
		*prv = pFunctionList->C_DeriveKey(hSession,
		                                  &ckmDerivationMech,
		                                  ahPrivateKeys[0],
		                                  attrGOST28147_89DerivedKey,
		                                  arraysize(attrGOST28147_89DerivedKey),
		                                  phDerivedKey);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/************************************************************************
		* Получить буфер со значением общего ключа ГОСТ 28147-89                *
		************************************************************************/
		printf(" Getting derived key value...\n");
		GetObjectValue(hSession,
		               pFunctionList,
		               *phDerivedKey,
		               &pbtDerivedKey,
		               &ulDerivedKeySize,
		               prv);
		if (*prv != CKR_OK)
			break;

		/************************************************************************
		* Распечатать буфер со значением общего ключа ГОСТ 28147-89             *
		************************************************************************/
		printf("Derived key data is:\n");
		for (i = 0;
		     i < ulDerivedKeySize;
		     i++)
		{
			printf("%02X ", pbtDerivedKey[i]);
			if ((i + 1) % 8 == 0)
				printf("\n");
		}
		break;
	}

	if (ahPrivateKeys)
	{
		free(ahPrivateKeys);
		ahPrivateKeys = NULL_PTR;
	}

	if (ahPublicKeys)
	{
		free(ahPublicKeys);
		ahPublicKeys = NULL_PTR;
	}

	if (ckDeriveParams.pPublicData)
	{
		free(ckDeriveParams.pPublicData);
		ckDeriveParams.pPublicData = NULL_PTR;
		ckDeriveParams.ulPublicDataLen = 0;
	}

	if (pbtDerivedKey)
	{
		free(pbtDerivedKey);
		pbtDerivedKey = NULL_PTR;
	}

	if (*prv != CKR_OK)
	{
		pFunctionList->C_DestroyObject(hSession,
		                               *phDerivedKey);
		*phDerivedKey = NULL_PTR;
	}

	if ((*prv != CKR_OK) || (ulPublicKeysNumber == 0) || (ulPrivateKeysNumber == 0))
		printf("\nDeriving failed!\n\n");
	else
		printf("Deriving has been completed successfully.\n\n");

	return *prv == CKR_OK;
}

/************************************************************************
* main()                                                                *
************************************************************************/
int main(void)
{
	HMODULE hModule = NULL_PTR;                          // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;               // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;   // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                    // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                            // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE hDerivedKey_1 = NULL_PTR;           // Хэндл выработанного на стороне отправителя общего ключа
	CK_OBJECT_HANDLE hDerivedKey_2 = NULL_PTR;           // Хэндл выработанного на стороне получателя общего ключа

	CK_BYTE_PTR pbtSessionKey = NULL_PTR;                // Указатель на буфер, содержащий сессионный ключ

	CK_BYTE_PTR pbtWrappedKey = NULL_PTR;                // Указатель на буфер, содержащий маскированный на стороне отправителя сессионный ключ
	CK_ULONG ulWrappedKeySize = 0;                       // Размер буфера со значением маскированного на стороне отправителя сессионного ключа, в байтах

	CK_BYTE_PTR pbtUnwrappedKey = NULL_PTR;              // Указатель на буфер, содержащий демаскированный на стороне получателя сессионный ключ
	CK_ULONG ulUnwrappedKeySize = 0;                     // Размер буфера со значением демаскированного на стороне получателя сессионного ключа, в байтах

	CK_OBJECT_HANDLE hTempKey = NULL_PTR;                // Хэндл ключа, который будет маскироваться/демаскироваться

	CK_RV rv = CKR_OK;                                   // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                               // Вспомогательная переменная для хранения кода возврата

	DWORD i = 0;                                         // Вспомогательная переменная-счетчик в циклах

	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Выполнить действия для начала работы с библиотекой PKCS#11.  *
		**********************************************************************/
		printf("Initialization module...\n");
		while (TRUE)
		{
			/**********************************************************************
			* 1.1 Загрузить библиотеку                                            *
			**********************************************************************/
			printf(" Loading library %s", PKCS11ECP_LIBRARY_NAME);
			hModule = LoadLibrary(PKCS11ECP_LIBRARY_NAME);
			if (hModule == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 1.2 Получить адрес функции запроса структуры с указателями на функции *
			************************************************************************/
			printf(" Getting GetFunctionList function");
			pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule,
			                                                         "C_GetFunctionList");
			if (pfGetFunctionList == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.3 Получить структуру с указателями на функции                     *
			**********************************************************************/
			printf(" Getting function list");
			rv = pfGetFunctionList(&pFunctionList);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.4 Инициализировать библиотеку                                     *
			**********************************************************************/
			printf(" Initializing library");
			rv = pFunctionList->C_Initialize(NULL_PTR);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.5 Получить количество слотов c подключенными токенами             *
			**********************************************************************/
			printf(" Getting number of connected slots");
			rv = pFunctionList->C_GetSlotList(CK_TRUE,
			                                  NULL_PTR,
			                                  &ulSlotCount);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			if (ulSlotCount == 0)
			{
				printf(" No Rutoken ECP is available!\n");
				break;
			}

			aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
			memset(aSlots,
			       0,
			       (ulSlotCount * sizeof(CK_SLOT_ID)));

			/**********************************************************************
			* 1.6 Получить список слотов c подключенными токенами                 *
			**********************************************************************/
			printf(" Getting list of connected slots");
			rv = pFunctionList->C_GetSlotList(CK_TRUE,
			                                  aSlots,
			                                  &ulSlotCount);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			printf(" Slots available: 0x%8.8X\n", (int)ulSlotCount);

			/**********************************************************************
			* 1.7 Открыть RW сессию в первом доступном слоте                      *
			**********************************************************************/
			printf(" Opening Session");
			rv = pFunctionList->C_OpenSession(aSlots[0],
			                                  CKF_SERIAL_SESSION | CKF_RW_SESSION,
			                                  NULL_PTR,
			                                  NULL_PTR,
			                                  &hSession);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.8 Выполнить аутентификацию с правами Пользователя                 *
			**********************************************************************/
			printf(" Logging in");
			rv = pFunctionList->C_Login(hSession,
			                            CKU_USER,
			                            USER_PIN,
			                            sizeof(USER_PIN));
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");
			break;
		}

		if ((rv != CKR_OK) || (ulSlotCount == 0))
		{
			printf("Initialization failed!\n");
			break;
		}
		else
			printf("Initialization has been completed successfully.\n");

		/**********************************************************************
		* Шаг 2: Выполнить предварительные действия для выработки ключа и     *
		*        маскирования.                                                *
		**********************************************************************/

		/**********************************************************************
		* 2.1 Установить параметры в структуре типа CK_GOSTR3410_DERIVE_PARAMS*
		* для выработки общего ключа                                          *
		**********************************************************************/
		ckDeriveParams.ulUKMLen = 8;
		GenerateRandomData(ckDeriveParams.ulUKMLen,
		                   &(ckDeriveParams.pUKM));

		/**********************************************************************
		* 2.2 Установить параметры в структуре типа CK_MECHANISM              *
		* для маскирования ключа                                              *
		**********************************************************************/
		ckmWrapMech.ulParameterLen = 8;
		GenerateRandomData(ckmWrapMech.ulParameterLen,
		                   (PBYTE *)&ckmWrapMech.pParameter);

		/**********************************************************************
		* 2.3 Заполнить шаблон сессионного ключа случайными данными           *
		**********************************************************************/
		GenerateRandomData(GOST_28147_KEY_SIZE,
		                   &pbtSessionKey);

		for (i = 0;
		     i < arraysize(attrGOST28147_89KeyToWrap);
		     i++)
			if (attrGOST28147_89KeyToWrap[i].type == CKA_VALUE)
			{
				attrGOST28147_89KeyToWrap[i].pValue = pbtSessionKey;
				attrGOST28147_89KeyToWrap[i].ulValueLen = GOST_28147_KEY_SIZE;
				break;
			}

		printf("\nSession key data is:\n");
		for (i = 0;
		     i < GOST_28147_KEY_SIZE;
		     i++)
		{
			printf("%02X ", pbtSessionKey[i]);
			if ((i + 1) % 8 == 0)
				printf("\n");
		}

		/**********************************************************************
		* Шаг 3: Выработать общий ключ на стороне отправителя.                *
		**********************************************************************/
		DeriveKey(hSession,
		          pFunctionList,
		          attrSenderPrivateKey,
		          arraysize(attrSenderPrivateKey),
		          attrRecipientPublicKey,
		          arraysize(attrRecipientPublicKey),
		          &hDerivedKey_1,
		          &rv);
		if ((rv != CKR_OK) || (!hDerivedKey_1))
			break;

		/**********************************************************************
		* Шаг 4: Маскировать сессионный ключ с помощью общего выработанного   *
		*        ключа на стороне отправителя.                                *
		**********************************************************************/
		printf("Wrapping key...\n");
		while (TRUE)
		{
			/************************************************************************
			* 4.1 Создать ключ, который будет маскирован                            *
			************************************************************************/
			printf(" Creating the GOST 28147-89 key to wrap");
			rv = pFunctionList->C_CreateObject(hSession,
			                                   attrGOST28147_89KeyToWrap,
			                                   arraysize(attrGOST28147_89KeyToWrap),
			                                   &hTempKey);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 4.2 Получить размер буфера, содержащего значение маскированного ключа *
			************************************************************************/
			printf(" Defining wrapping key size");
			rv = pFunctionList->C_WrapKey(hSession,
			                              &ckmWrapMech,
			                              hDerivedKey_1,
			                              hTempKey,
			                              NULL_PTR,
			                              &ulWrappedKeySize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtWrappedKey = (CK_BYTE*)malloc(ulWrappedKeySize);
			memset(pbtWrappedKey,
			       0,
			       ulWrappedKeySize * sizeof(CK_BYTE));

			/************************************************************************
			* 4.3 Получить маскированный ключ                                       *
			************************************************************************/
			printf(" Wrapping key");
			rv = pFunctionList->C_WrapKey(hSession,
			                              &ckmWrapMech,
			                              hDerivedKey_1,
			                              hTempKey,
			                              pbtWrappedKey,
			                              &ulWrappedKeySize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 4.4 Распечатать буфер, содержащий маскированный ключ                  *
			************************************************************************/
			printf("Wrapped key data is:\n");
			for (i = 0;
			     i < ulWrappedKeySize;
			     i++)
			{
				printf("%02X ", pbtWrappedKey[i]);
				if ((i + 1) % 9 == 0)
					printf("\n");
			}
			break;
		}

		if (hTempKey)
		{
			pFunctionList->C_DestroyObject(hSession,
			                               hTempKey);
			hTempKey = NULL_PTR;
		}

		if (rv == CKR_OK)
			printf("\nWrapping has been completed successfully.\n");
		else
		{
			printf("\nWrapping failed!\n");
			break;
		}

		/**********************************************************************
		* Шаг 5: Выработать общий ключ на стороне получателя.                 *
		**********************************************************************/
		DeriveKey(hSession,
		          pFunctionList,
		          attrRecipientPrivateKey,
		          arraysize(attrRecipientPrivateKey),
		          attrSenderPublicKey,
		          arraysize(attrSenderPublicKey),
		          &hDerivedKey_2,
		          &rv);
		if ((rv != CKR_OK) || (hDerivedKey_2 == 0))
			break;

		/**********************************************************************
		* Шаг 6: Демаскировать сессионный ключ с помощью общего выработанного *
		*        ключа на стороне получателя.                                 *
		**********************************************************************/
		printf("Unwrapping key...\n");
		while (TRUE)
		{
			/************************************************************************
			* 6.1 Демаскировать ключ                                                *
			************************************************************************/
			printf(" Unwrapping key");
			rv = pFunctionList->C_UnwrapKey(hSession,
			                                &ckmWrapMech,
			                                hDerivedKey_2,
			                                pbtWrappedKey,
			                                ulWrappedKeySize,
			                                attrGOST28147_89UnwrappedKey,
			                                arraysize(attrGOST28147_89UnwrappedKey),
			                                &hTempKey);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 6.2 Получить буфер со значением демаскированного ключа                *
			************************************************************************/
			printf(" Getting unwrapped key value...\n");
			GetObjectValue(hSession,
			               pFunctionList,
			               hTempKey,
			               &pbtUnwrappedKey,
			               &ulUnwrappedKeySize,
			               &rv);
			if (rv != CKR_OK)
				break;

			/************************************************************************
			* 6.3 Распечатать буфер со значением демаскированного ключа             *
			************************************************************************/
			printf("Unwrapped key data:\n");
			for (i = 0;
			     i < ulUnwrappedKeySize;
			     i++)
			{
				printf("%02X ", pbtUnwrappedKey[i]);
				if ((i + 1) % 8 == 0)
					printf("\n");
			}
			break;
		}

		if (hTempKey)
		{
			pFunctionList->C_DestroyObject(hSession,
			                               hTempKey);
			hTempKey = NULL_PTR;
		}

		if (rv == CKR_OK)
			printf("Unwrapping has been completed successfully.\n\n");
		else
		{
			printf("\nUnwrapping failed!\n\n");
			break;
		}

		/**********************************************************************
		* Шаг 7: Сравнить первоначальное значение сессионного ключа           *
		*        со значением демаскированного ключа.                         *
		**********************************************************************/
		if ((ulUnwrappedKeySize != GOST_28147_KEY_SIZE)
		    || (memcmp(pbtSessionKey,
		               pbtUnwrappedKey,
		               GOST_28147_KEY_SIZE) != 0))
			printf("\nThe unwrapped key is not equal to the session key!\n");
		else
			printf("The unwrapped key is equal to the session key.\n");
		break;
	}

	if (hDerivedKey_1)
	{
		pFunctionList->C_DestroyObject(hSession,
		                               hDerivedKey_1);
		hDerivedKey_1 = NULL_PTR;
	}

	if (hDerivedKey_2)
	{
		pFunctionList->C_DestroyObject(hSession,
		                               hDerivedKey_2);
		hDerivedKey_2 = NULL_PTR;
	}
	/**********************************************************************
	* Шаг 8: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");
	if (hSession)
	{
		/**********************************************************************
		* 8.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 8.2 Закрыть все открытые сессии в слоте                             *
		**********************************************************************/
		printf(" C_CloseAllSession");
		rvTemp = pFunctionList->C_CloseAllSessions(aSlots[0]);
		if (rvTemp != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hSession = NULL_PTR;
	}

	if (pFunctionList)
	{
		/**********************************************************************
		* 8.3 Деинициализировать библиотеку                                   *
		**********************************************************************/
		printf(" Finalizing library");
		rvTemp = pFunctionList->C_Finalize(NULL_PTR);
		if (rvTemp != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		pFunctionList = NULL_PTR;
	}

	if (hModule)
	{
		/**********************************************************************
		* 8.4 Выгрузить библиотеку из памяти                                  *
		**********************************************************************/
		printf(" Unloading");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hModule = NULL_PTR;
	}

	if (ckDeriveParams.pUKM)
	{
		free(ckDeriveParams.pUKM);
		ckDeriveParams.pUKM = NULL_PTR;
	}

	if (ckmWrapMech.pParameter)
	{
		free(ckmWrapMech.pParameter);
		ckmWrapMech.pParameter = NULL_PTR;
	}

	if (pbtSessionKey)
	{
		free(pbtSessionKey);
		pbtSessionKey = NULL_PTR;
	}

	if (pbtUnwrappedKey)
	{
		free(pbtUnwrappedKey);
		pbtUnwrappedKey = NULL_PTR;
	}

	if (pbtWrappedKey)
	{
		free(pbtWrappedKey);
		pbtWrappedKey = NULL_PTR;
	}

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if (rvTemp != CKR_OK)
		printf("Unloading failed!\n\n");
	else
		printf("Unloading has been completed successfully.\n\n");

	if ((rv != CKR_OK) || (ulSlotCount == 0))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");


	getchar();
	return rv != CKR_OK;
}

