/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд инициализации Рутокен:                            *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - инициализация токена;                                               *
*  - выполнение аутентификации с правами Администратора;                 *
*  - инициализация PIN-кода Пользователя;                                *
*  - сброс прав доступа Администратора и закрытие соединения с Рутокен.  *
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
	HMODULE hModule = NULL_PTR;                            // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                 // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;         // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;     // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                      // Указатель на массив идентификаторов всех доступных слотов
	CK_ULONG ulSlotCount = 0;                              // Количество идентификаторов всех доступных слотов в массиве

	CK_RV rv = CKR_OK;                                     // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                 // Вспомогательная переменная для хранения кода возврата

	printf("Initialization module...\n");
	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Загрузить библиотеку.                                        *
		**********************************************************************/
		printf(" Loading library %s", PKCS11_LIBRARY_NAME);   // или PKCS11ECP_LIBRARY_NAME
		hModule = LoadLibrary(PKCS11_LIBRARY_NAME);
		if (hModule == NULL_PTR)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 2: Получить адрес функции запроса структуры с указателями       *
		*        на функции.                                                  *
		**********************************************************************/
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
		* Шаг 3: Получить структуру с указателями на функции.                 *
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
		* Шаг 4: Инициализировать библиотеку.                                 *
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
		* Шаг 5: Получить количество слотов c подключенными токенами          *
		**********************************************************************/
		/* Определение количества подключенных слотов */
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
			printf(" No Rutoken is available!\n");
			break;
		}

		aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
		memset(aSlots,
		       0,
		       (ulSlotCount * sizeof(CK_SLOT_ID)));

		/**********************************************************************
		* Шаг 6: Получить список слотов c подключенными токенами              *
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
		* Шаг 7: Инициализировать токен.                                      *
		**********************************************************************/
		printf(" C_InitToken");
		rv = pFunctionList->C_InitToken(aSlots[0],
		                                SO_PIN,
		                                sizeof(SO_PIN),
		                                TOKEN_LABEL);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 8: Открыть сессию в первом доступном слоте.                     *
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
		* Шаг 9: Выполнить аутентификацию с правами Администратора.           *
		**********************************************************************/
		printf(" Login Administrator");
		rv = pFunctionList->C_Login(hSession,
		                            CKU_SO,
		                            SO_PIN,
		                            sizeof(SO_PIN));
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 10: Инициализировать PIN-код Пользователя.                      *
		**********************************************************************/
		printf(" Initializing User PIN ");
		rv = pFunctionList->C_InitPIN(hSession,
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
		printf("Initialization failed!\n");
	else
		printf("Initialization has been completed successfully.\n");

	printf("\nFinalizing... \n");


	if (hSession)
	{
		/**********************************************************************
		* Шаг 11: Сбросить права доступа                                      *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* Шаг 11: Закрыть все открытые сессии в слоте                         *
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
		* Шаг 12: Деинициализировать библиотеку                               *
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
		* Шаг 13: Выгрузить библиотеку из памяти                              *
		**********************************************************************/
		printf(" Unloading library");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hModule = NULL_PTR;
	}

	if (rvTemp == CKR_OK)
		printf("Unloading has been completed successfully.\n\n");
	else
		printf("Unloading failed!\n\n");

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
