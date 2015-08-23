/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример использования функций расширения компании "Актив"               *
* стандарта PKCS#11:                                                     *
*  - установление соединения с Rutoken в первом доступном слоте;         *
*  - выполнение инициализации токена;                                    *
*  - блокирование PIN-кода Пользователя;                                 *
*  - разблокирование PIN-кода Пользователя;                              *
*  - задание новой метки токена;                                         *
*  - вывод информации о токене.                                          *
*------------------------------------------------------------------------*
* Данный пример является самодостаточным из серии примеров работы        *
* с библиотекой PKCS#11                                                  *
*************************************************************************/

#include "Common.h"

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                                      // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                           // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;                   // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;               // Указатель на функцию C_GetFunctionList

	CK_FUNCTION_LIST_EXTENDED_PTR pFunctionListEx = NULL_PTR;        // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
	CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = NULL_PTR;  // Указатель на функцию C_EX_GetFunctionListExtended
	CK_TOKEN_INFO_EXTENDED tokenInfoEx;                              // Структура данных типа CK_TOKEN_INFO_EXTENDED с информацией о токене

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                                // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                                        // Количество идентификаторов слотов в массиве

	CK_BBOOL bIsRutokenECP = FALSE;                                  // Вспомогательная переменная для хранения признака типа токена
	CK_RUTOKEN_INIT_PARAM initInfo_st;                               // Структура данных типа CK_RUTOKEN_INIT_PARAM, содержащая параметры для работы функции C_EX_InitToken

	CK_RV rv = CKR_OK;                                               // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                           // Вспомогательная переменная для хранения кода возврата

	DWORD i = 0;                                                     // Вспомогательная переменная-счетчик для циклов

	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Загрузка библиотеки.                                         *
		**********************************************************************/
		printf("Loading library %s", PKCS11_LIBRARY_NAME);   // или PKCS11ECP_LIBRARY_NAME
		hModule = LoadLibrary(PKCS11_LIBRARY_NAME);
		if (hModule == NULL_PTR)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 2: Получение адреса функции запроса структуры с указателями     *
		*        на функции стандарта PKCS#11.                                *
		**********************************************************************/
		printf("Getting GetFunctionList function");
		pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule,
		                                                         "C_GetFunctionList");
		if (pfGetFunctionList == NULL_PTR)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 3: Получение адреса функции запроса структуры с указателями     *
		*        на функции расширения стандарта PKCS#11.                     *
		**********************************************************************/
		printf("Getting GetFunctionListExtended function");
		pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(hModule,
		                                                                      "C_EX_GetFunctionListExtended");
		if (pfGetFunctionListEx == NULL_PTR)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 4: Получение структуры с указателями на функции                 *
		*        стандарта PKCS#11.                                           *
		**********************************************************************/
		printf("Getting function list");
		rv = pfGetFunctionList(&pFunctionList);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 5: Получение структуры с указателями на функции расширения      *
		*        стандарта PKCS#11.                                           *
		**********************************************************************/
		printf("Getting extended function list");
		rv = pfGetFunctionListEx(&pFunctionListEx);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 6: Инициализация библиотеки.                                    *
		**********************************************************************/
		printf("Initializing library");
		rv = pFunctionList->C_Initialize(NULL_PTR);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 7: Получение количества слотов c подключенными токенами         *
		**********************************************************************/
		printf("Getting number of connected slots");
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
			printf("No Rutoken is available!\n");
			break;
		}

		aSlots = (CK_SLOT_ID*)malloc(sizeof(ulSlotCount));
		memset(aSlots,
		       0,
		       (ulSlotCount * sizeof(CK_SLOT_ID)));

		/**********************************************************************
		* Шаг 8: Получение списка слотов c подключенными токенами             *
		**********************************************************************/
		printf("Getting list of connected slots");
		rv = pFunctionList->C_GetSlotList(CK_TRUE,
		                                  aSlots,
		                                  &ulSlotCount);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		printf("Slots available: 0x%8.8X\n", (int)ulSlotCount);

		/**********************************************************************
		* Шаг 9: Получение расширенной информации о подключенном токене       *
		**********************************************************************/
		printf("Determining token type");
		tokenInfoEx.ulSizeofThisStructure = sizeof(tokenInfoEx);
		rv = pFunctionListEx->C_EX_GetTokenInfoExtended(aSlots[0],
		                                                &tokenInfoEx);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}

		/**********************************************************************
		* Шаг 10: Определение класса токена                                   *
		**********************************************************************/
		if (tokenInfoEx.ulTokenClass == TOKEN_CLASS_ECP)
		{
			bIsRutokenECP = TRUE;
			printf(": Rutoken ECP\n");
		}
		else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_LITE)
		{
			bIsRutokenECP = TRUE;
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
		* Шаг 11: Заполнение полей структуры CK_RUTOKEN_INIT_PARAM            *
		**********************************************************************/
		printf("Initializing token");
		memset(&initInfo_st,
		       0,
		       sizeof(CK_RUTOKEN_INIT_PARAM));

		initInfo_st.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM);
		initInfo_st.UseRepairMode = 0;
		initInfo_st.pNewAdminPin = SO_PIN;
		initInfo_st.ulNewAdminPinLen = sizeof(SO_PIN);
		initInfo_st.pNewUserPin = NEW_USER_PIN;
		initInfo_st.ulNewUserPinLen = sizeof(NEW_USER_PIN);
		initInfo_st.ulMinAdminPinLen = bIsRutokenECP ? 6 : 1;
		initInfo_st.ulMinUserPinLen = bIsRutokenECP ? 6 : 1;
		initInfo_st.ChangeUserPINPolicy = (TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN);
		initInfo_st.ulMaxAdminRetryCount = MAX_ADMIN_RETRY_COUNT;
		initInfo_st.ulMaxUserRetryCount = MAX_USER_RETRY_COUNT;
		initInfo_st.pTokenLabel = TOKEN_STD_LABEL;
		initInfo_st.ulLabelLen = sizeof(TOKEN_STD_LABEL);

		/**********************************************************************
		* Шаг 12: Инициализация токена                                        *
		**********************************************************************/
		rv = pFunctionListEx->C_EX_InitToken(aSlots[0],
		                                     SO_PIN,
		                                     arraysize(SO_PIN),
		                                     &initInfo_st);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 13: Открытие сессии в первом доступном слоте                    *
		**********************************************************************/
		printf("Opening Session");
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
		* Шаг 14: Тестирование блокировки/разблокировки PIN-кода Пользователя *
		**********************************************************************/
		printf("\nPerforming extended PIN function test...\n");
		while (TRUE)
		{
			printf(" Locking User PIN...\n");
			for (i = 1;
			     i < (MAX_USER_RETRY_COUNT + 1);
			     i++)
			{
				/************************************************************************
				* 14.1 Ввод неправильного PIN-кода Пользователя до блокировки PIN-кода  *
				************************************************************************/
				printf("  %i. C_Login with wrong User PIN:", (int)i);
				rv = pFunctionList->C_Login(hSession,
				                            CKU_USER,
				                            WRONG_USER_PIN,
				                            arraysize(WRONG_USER_PIN));
				if (rv == CKR_PIN_INCORRECT)
					printf(" -> Wrong PIN\n");
				else if (rv == CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				else
					printf(" -> OK\n");
			}

			/************************************************************************
			* 14.2 Выполнение аутентификации с правами Администратора               *
			************************************************************************/
			printf(" Unlocking User PIN...\n");
			printf("  Login SO");
			rv = pFunctionList->C_Login(hSession,
			                            CKU_SO,
			                            SO_PIN,
			                            arraysize(SO_PIN));
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 14.3 Разблокировать PIN-код Пользователя                              *
			************************************************************************/
			printf("  Unlock User PIN");
			rv = pFunctionListEx->C_EX_UnblockUserPIN(hSession);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 14.4 Сбросить права доступа                                           *
			************************************************************************/
			printf("  Logout SO ");
			rv = pFunctionList->C_Logout(hSession);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");
			break;
		}

		if (rv != CKR_OK)
		{
			printf("Extended PIN function test has been failed.\n\n");
			break;
		}
		else
			printf("Extended PIN function test has been completed successfully.\n\n");

		/**********************************************************************
		* Шаг 15: Аутентификация с правами Пользователя                       *
		**********************************************************************/
		printf("User authentification");
		rv = pFunctionList->C_Login(hSession,
		                            CKU_USER,
		                            NEW_USER_PIN,
		                            arraysize(NEW_USER_PIN));
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 16: Изменение метки токена на "длинную"                         *
		**********************************************************************/
		printf("Changing Token Name");
		rv = pFunctionListEx->C_EX_SetTokenName(hSession,
		                                        TOKEN_LONG_LABEL,
		                                        arraysize(TOKEN_LONG_LABEL));
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 17: Печать расширенной информации о токене                      *
		**********************************************************************/
		printf("Extended information:\n");
		printf(" Token type:               0x%8.8x ", (int)tokenInfoEx.ulTokenType);
		if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_ECP)
			printf("(Rutoken ECP) \n");
		else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_LITE)
			printf("(Rutoken LITE) \n");
		else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN)
			printf("(Rutoken) \n");

		printf(" Protocol number:          0x%8.8x \n", (int)tokenInfoEx.ulProtocolNumber);
		printf(" Microcode number:         0x%8.8x \n", (int)tokenInfoEx.ulMicrocodeNumber);
		printf(" Flags:                    0x%8.8x \n", (int)tokenInfoEx.flags);
		printf(" Max Admin PIN Len:        0x%8.8x \n", (int)tokenInfoEx.ulMaxAdminPinLen);
		printf(" Min Admin PIN Len:        0x%8.8x \n", (int)tokenInfoEx.ulMinAdminPinLen);
		printf(" Max User PIN Len:         0x%8.8x \n", (int)tokenInfoEx.ulMaxUserPinLen);
		printf(" Min User PIN Len:         0x%8.8x \n", (int)tokenInfoEx.ulMinUserPinLen);
		printf(" Max Admin retry counter:  0x%8.8x \n", (int)tokenInfoEx.ulMaxAdminRetryCount);
		printf(" Admin retry counter:      0x%8.8x \n", (int)tokenInfoEx.ulAdminRetryCountLeft);
		printf(" Max User retry counter:   0x%8.8x \n", (int)tokenInfoEx.ulMaxUserRetryCount);
		printf(" User retry counter:       0x%8.8x \n", (int)tokenInfoEx.ulUserRetryCountLeft);
		printf(" Serial number:            ");
		for (i = 0;
		     i < arraysize(tokenInfoEx.serialNumber);
		     i++)
			printf("%02X ", tokenInfoEx.serialNumber[i]);
		printf("\n Total memory:             0x%8.8x \n", (int)tokenInfoEx.ulTotalMemory);
		printf(" Free memory:              0x%8.8x \n", (int)tokenInfoEx.ulFreeMemory);
		printf(" ATR:                      ");
		for (i = 0;
		     i < tokenInfoEx.ulATRLen;
		     i++)
			printf("%02X ", (int)tokenInfoEx.ATR[i]);
		printf("\nExtended info test has been completed successfully.\n\n");

		/**********************************************************************
		* Шаг 18: Установка PIN-кода Пользователя по умолчанию                *
		**********************************************************************/
		printf("Changing User PIN to default");
		rv = pFunctionList->C_SetPIN(hSession,
		                             NEW_USER_PIN,
		                             arraysize(NEW_USER_PIN),
		                             USER_PIN,
		                             arraysize(USER_PIN));
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");
		break;
	}

	/**********************************************************************
	* Шаг 19: Завершения работы с библиотекой PKCS#11.                    *
	**********************************************************************/
	printf("\nFinalizing... \n");

	if (hSession)
	{
		/**********************************************************************
		* 19.1 Сбросить права доступа                                         *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 19.2 Закрыть все открытые сессии в слоте                            *
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
		* 19.3 Деинициализировать библиотеку                                  *
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
		* 19.4 Выгрузить библиотеку из памяти                                 *
		**********************************************************************/
		printf(" Unloading library");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hModule = NULL_PTR;
	}

	if (rvTemp != CKR_OK)
		printf("Unloading failed!\n\n");
	else
		printf("Unloading has been completed successfully.\n\n");

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if ((rv != CKR_OK) || (ulSlotCount == 0))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}

