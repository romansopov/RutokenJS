/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11           * 
* на языке C                                                             *
*------------------------------------------------------------------------*
* Использование команд создания объектов в памяти Рутокен PINPad:        *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - определение модели подключенного устройства;                        *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - создание ключевой пары ГОСТ Р 34.10-2001 с атрибутами подтверждения *
*    подписи данных и вводом PIN-кода на экране PINPad;                  *
*  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
*    соединения с Рутокен PINPad.                                        *
*------------------------------------------------------------------------*
* Данный пример является одним из серии примеров работы с библиотекой    *
* PKCS#11. Созданные примером объекты используются также и в других      *
* примерах работы с библиотекой PKCS#11.                                 *
*************************************************************************/

#include <Common.h>

/************************************************************************
* Шаблон для создания открытого ключа ГОСТ Р 34.10-2001                 *
************************************************************************/
CK_ATTRIBUTE attrGOST34_10_2001ExchPublicKeyTmpl_1[] =
{
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey)},                      // Объект открытого ключа ГОСТ Р 34.10-2001 (#1)
	{ CKA_LABEL, &PubLabelGOST1, sizeof(PubLabelGOST1) - 1},        // Метка ключа
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},         // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktGOST34_10_2001, sizeof(ktGOST34_10_2001)},   // Тип ключа
	{ CKA_ENCRYPT, &bTrue, sizeof(bTrue)},                          // Ключ предназначен для зашифрования
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Ключ доступен без авторизации на токене
	{ CKA_DERIVE, &bTrue, sizeof(bTrue)},                           // Ключ поддерживает деривацию (из него могут быть получены другие ключи).
	{ CKA_VENDOR_KEY_CONFIRM_OP, &bTrue, sizeof(bTrue)},            // Операция подписи требует подтверждения на PINPad
//	{ CKA_VENDOR_KEY_PIN_ENTER, &bTrue, sizeof(bTrue) },            // Операция подписи требует ввода PIN-кода на PINPad
	{ CKA_GOSTR3410_PARAMS, GOST3410_params_oid, sizeof(GOST3410_params_oid)}, // Параметры алгоритма ГОСТ Р 34.10-2001
	{ CKA_GOSTR3411_PARAMS, GOST3411_params_oid, sizeof(GOST3411_params_oid)}  // Параметры алгоритма ГОСТ Р 34.11-1994
};

/************************************************************************
* Шаблон для создания закрытого ключа ГОСТ Р 34.10-2001                 *
************************************************************************/
CK_ATTRIBUTE attrGOST34_10_2001ExchPrivateKeyTmpl_1[] =
{
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey)},                    // Объект закрытого ключа ГОСТ Р 34.10-2001 (#1)
	{ CKA_LABEL, &PrivLabelGOST1, sizeof(PrivLabelGOST1) - 1},      // Метка ключа
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},         // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktGOST34_10_2001, sizeof(ktGOST34_10_2001)},   // Тип ключа
	{ CKA_DECRYPT, &bTrue, sizeof(bTrue)},                          // Ключ предназначен для расшифрования
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_PRIVATE, &bTrue, sizeof(bTrue)},                          // Ключ доступен только после авторизации на токене
	{ CKA_DERIVE, &bTrue, sizeof(bTrue)},                           // Ключ поддерживает деривацию (из него могут быть получены другие ключи)
	{ CKA_VENDOR_KEY_CONFIRM_OP, &bTrue, sizeof(bTrue) },           // Операция подписи требует подтверждения на PINPad
//	{ CKA_VENDOR_KEY_PIN_ENTER, &bTrue, sizeof(bTrue) },            // Операция подписи требует ввода PIN-кода на PINPad
	{ CKA_GOSTR3410_PARAMS, GOST3410_params_oid, sizeof(GOST3410_params_oid)} // Параметры алгоритма ГОСТ Р 34.10-2001
};

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                                     // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                          // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;                  // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;              // Указатель на функцию C_GetFunctionList

	CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = NULL_PTR; // Указатель на функцию C_EX_GetFunctionListExtended
	CK_FUNCTION_LIST_EXTENDED_PTR pFunctionListEx = NULL_PTR;       // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
	CK_TOKEN_INFO_EXTENDED tokenInfoEx;                             // Структура данных типа CK_TOKEN_INFO_EXTENDED с информацией о токене

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                               // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                                       // Количество идентификаторов слотов в массиве

	CK_BBOOL bIsRutokenECP = FALSE;                                 // Вспомогательная переменная для хранения признака типа токена
	CK_RV rv = CKR_OK;                                              // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                          // Вспомогательная переменная для хранения кода возврата

	CK_OBJECT_HANDLE hGOST34_10_2001ExchPublicKey_1 = NULL_PTR;     // Хэндл открытого ключа ГОСТ Р 34.10-2001 (первая ключевая пара для подписи и шифрования)
	CK_OBJECT_HANDLE hGOST34_10_2001ExchPrivateKey_1 = NULL_PTR;    // Хэндл закрытого ключа ГОСТ Р 34.10-2001 (первая ключевая пара для подписи и шифрования)

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
			printf("Loading library %s", PKCS11ECP_LIBRARY_NAME);
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
				printf(" -> Failed %X\n", (int)rv);
				break;
			}
			printf(" -> OK\n");

			printf(" Slots available: 0x%8.8X\n", (int)ulSlotCount);

			/**********************************************************************
			* 1.7 Определить класс токена                                         *
			**********************************************************************/
			printf(" Determining token type");

			/**********************************************************************
			* Получить адрес функции запроса структуры с указателями на функции   *
			* расширения                                                          *
			**********************************************************************/
			pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(hModule,
			                                                                      "C_EX_GetFunctionListExtended");
			if (pfGetFunctionListEx == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}

			/**********************************************************************
			* Получить структуру с указателями на функции расширения              *
			**********************************************************************/
			rv = pfGetFunctionListEx(&pFunctionListEx);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}

			memset(&tokenInfoEx,
			       0,
			       sizeof(CK_TOKEN_INFO_EXTENDED));
			tokenInfoEx.ulSizeofThisStructure = sizeof(CK_TOKEN_INFO_EXTENDED);

			/**********************************************************************
			* Получить расширенную информацию о подключенном токене               *
			**********************************************************************/
			rv = pFunctionListEx->C_EX_GetTokenInfoExtended(aSlots[0],
			                                                &tokenInfoEx);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}

			/**********************************************************************
			* Определить класс токена                                             *
			**********************************************************************/
			if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY)
			{
				bIsRutokenECP = TRUE;
				printf(": Rutoken PINPad\n");
			}
			else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_ECP)
			{
				bIsRutokenECP = FALSE;
				printf(": Rutoken ECP\n");
			}
			else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_LITE)
			{
				bIsRutokenECP = FALSE;
				printf(": Rutoken Lite\n");
			}
			else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN)
			{
				bIsRutokenECP = FALSE;
				printf(": Rutoken / Rutoken S\n");
			}
			else
			{
				bIsRutokenECP = FALSE;
				printf(": undefined\n");
			}

			/**********************************************************************
			* 1.8 Открыть RW сессию в первом доступном слоте                      *
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
			* 1.9 Выполнить аутентификацию Пользователя                           *
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
		* Шаг 2: Создать объекты.                                             *
		**********************************************************************/
		printf("\nGenerating GOST R 34.10-2001 exchange key pairs...");

		if (bIsRutokenECP)
		{
			/**********************************************************************
			* 2.1 Сгенерировать первую ключевую пару ГОСТ Р 34.10-2001            *
			**********************************************************************/
			printf("\n Generating key pair");
			rv = pFunctionList->C_GenerateKeyPair(hSession,                                             // Хэндл открытой сессии
			                                      &ckmGOST34_10_2001KeyGenMech,                         // Используемый механизм генерации ключевой пары ГОСТ Р 34.10-2001
			                                      attrGOST34_10_2001ExchPublicKeyTmpl_1,                // Шаблон открытого ключа ГОСТ Р 34.10-2001
			                                      arraysize(attrGOST34_10_2001ExchPublicKeyTmpl_1),     // Размер шаблона открытого ключа
			                                      attrGOST34_10_2001ExchPrivateKeyTmpl_1,               // Шаблон закрытого ключа ГОСТ Р 34.10-2001
			                                      arraysize(attrGOST34_10_2001ExchPrivateKeyTmpl_1),    // Размер шаблона закрытого ключа
			                                      &hGOST34_10_2001ExchPublicKey_1,                      // Хэндл открытого ключа ГОСТ Р 34.10-2001
			                                      &hGOST34_10_2001ExchPrivateKey_1);                    // Хэндл закрытого ключа ГОСТ Р 34.10-2001
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n"
				       "Generation GOST key pairs failed!\n");
				break;
			}
			printf(" -> OK\n");

			printf("Generation GOST key pair has been completed successfully.\n");

			break;
		}
		else
			printf("\n No Rutoken ECP is available!\n"
			       "Generation GOST key pairs failed!\n");
		break;
	}

	/**********************************************************************
	* Шаг 3: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");

	if (hSession)
	{
		/**********************************************************************
		* 3.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 3.2 Закрыть все открытые сессии в слоте                             *
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
		* 3.3 Деинициализировать библиотеку                                   *
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
		* 3.4 Выгрузить библиотеку из памяти                                  *
		**********************************************************************/
		printf(" Unloading library");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hModule = NULL_PTR;
	}

	if (rvTemp != CKR_OK)
		printf("Unloading library failed!\n\n");
	else
		printf("Unloading library has been completed successfully.\n\n");

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if ((rv != CKR_OK) || (ulSlotCount == 0) || (!bIsRutokenECP))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}

