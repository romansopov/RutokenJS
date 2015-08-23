/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд получения информации о доступных слотах           *
* и токенах:                                                             *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - получение информации о библиотеке PKCS#11;                          *
*  - получение информации о доступных слотах;                            *
*  - получение информации о подключенных токенах;                        *
*  - получение информации о поддерживаемых механизмах.                   *
*------------------------------------------------------------------------*
* Данный пример является самодостаточным из серии примеров работы        *
* с библиотекой PKCS#11                                                  *
*************************************************************************/

#include "Common.h"

/************************************************************************
* Распечатать инфомацию:                                                *
*  - о слотах;                                                          *
*  - подключенных токенах;                                              *
*  - поддерживаемых механизмах.                                         *
************************************************************************/
BOOL PrintSlotInfo(IN CK_FUNCTION_LIST_PTR pFunctionList,    // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
                   IN CK_SLOT_ID slotID,                     // Идентификатор слота
                   OUT CK_RV* prv                            // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
                   )
{
	CK_SLOT_INFO slotInfo;                             // Структура данных типа CK_SLOT_INFO с информацией о слоте
	CK_TOKEN_INFO tokenInfo;                           // Структура данных типа CK_TOKEN_INFO с информацией о токене
	CK_MECHANISM_INFO mechInfo;                        // Структура данных типа CK_MECHANISM_INFO с информацией о механизме

	CK_MECHANISM_TYPE_PTR aMechanisms = NULL_PTR;      // Указатель на массив механизмов, поддерживаемых слотом
	CK_ULONG ulMechanismCount = 0;                     // Количество идентификаторов механизмов в массиве

	DWORD i = 0;                                       // Вспомогательная переменная-счетчик для циклов

	while (TRUE)
	{
		/************************************************************************
		* Получить информацию о слоте                                           *
		************************************************************************/
		memset(&slotInfo,
		       0,
		       sizeof(CK_SLOT_INFO));

		printf("C_GetSlotInfo");
		*prv = pFunctionList->C_GetSlotInfo(slotID,
		                                    &slotInfo);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/************************************************************************
		* Распечатать информацию о слоте                                        *
		************************************************************************/
		printf("Printing slot info:\n");
		printf(" Slot description:  %.*s \n", (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription);
		printf(" Manufacturer:      %.*s \n", (int)sizeof(slotInfo.manufacturerID), slotInfo.manufacturerID);
		printf(" Flags:             0x%8.8X \n", (int)slotInfo.flags);
		printf(" Hardware Ver:      %d.%d \n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
		printf(" Firmware Ver:      %d.%d \n\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);

		if (slotInfo.flags & CKF_TOKEN_PRESENT)
		{
			memset(&tokenInfo,
			       0,
			       sizeof(CK_TOKEN_INFO));

			/************************************************************************
			* Получить информацию о токене                                        *
			************************************************************************/
			printf("C_GetTokenInfo");
			*prv = pFunctionList->C_GetTokenInfo(slotID,
			                                     &tokenInfo);

			if (*prv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* Распечатать информацию о токене                                        *
			************************************************************************/
			printf("Printing token info:\n");
			printf(" Token label:               %.*s \n", (int)sizeof(tokenInfo.label), tokenInfo.label);
			printf(" Manufacturer:              %.*s \n", (int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID);
			printf(" Token model:               %.*s \n", (int)sizeof(tokenInfo.model), tokenInfo.model);
			printf(" Token #:                   %.*s \n", (int)sizeof(tokenInfo.serialNumber), tokenInfo.serialNumber);

			printf(" Flags:                     0x%8.8X \n", (int)tokenInfo.flags);
			printf(" Max session count:         0x%8.8X \n", (int)tokenInfo.ulMaxSessionCount);
			printf(" Current session count:     0x%8.8X \n", (int)tokenInfo.ulSessionCount);
			printf(" Max RW session count:      0x%8.8X \n", (int)tokenInfo.ulMaxRwSessionCount);
			printf(" Current RW session count:  0x%8.8X \n", (int)tokenInfo.ulRwSessionCount);
			printf(" Max PIN length:            0x%8.8X \n", (int)tokenInfo.ulMaxPinLen);
			printf(" Min PIN length:            0x%8.8X \n", (int)tokenInfo.ulMinPinLen);
			printf(" Total public memory:       0x%8.8X \n", (int)tokenInfo.ulTotalPublicMemory);
			printf(" Free public memory:        0x%8.8X \n", (int)tokenInfo.ulFreePublicMemory);
			printf(" Total private memory:      0x%8.8X \n", (int)tokenInfo.ulTotalPrivateMemory);
			printf(" Free private memory:       0x%8.8X \n", (int)tokenInfo.ulFreePrivateMemory);

			printf(" Hardware Ver:              %d.%d \n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
			printf(" Firmware Ver:              %d.%d \n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);

			printf(" Timer #:                   %.*s \n\n", (int)sizeof(tokenInfo.utcTime), tokenInfo.utcTime);

			/************************************************************************
			* Получить список механизмов                                            *
			************************************************************************/
			ulMechanismCount = 0;
			printf("C_GetMechanismList step 1");
			*prv = pFunctionList->C_GetMechanismList(slotID,
			                                         NULL_PTR,
			                                         &ulMechanismCount);

			if (*prv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			aMechanisms = (CK_MECHANISM_TYPE*)malloc(sizeof(CK_MECHANISM_TYPE) * ulMechanismCount);
			memset(aMechanisms,
			       0,
			       (sizeof(CK_MECHANISM_TYPE) * ulMechanismCount));

			printf("C_GetMechanismList step 2");
			*prv = pFunctionList->C_GetMechanismList(slotID,
			                                         aMechanisms,
			                                         &ulMechanismCount);
			if (*prv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			for (i = 0;
			     i < ulMechanismCount;
			     i++)
			{
				printf("\nMechanism info 0x%8.8X \n", (int)i);
				memset(&mechInfo,
				       0,
				       sizeof(CK_MECHANISM_INFO));

				/************************************************************************
				* Получить инфомацию о механизме                                        *
				************************************************************************/
				printf(" C_GetMechanismInfo");
				*prv = pFunctionList->C_GetMechanismInfo(slotID,
				                                         aMechanisms[i],
				                                         &mechInfo);
				if (*prv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				/************************************************************************
				* Распечатать инфомацию о механизме                                     *
				************************************************************************/
				printf(" Mechanism type:    0x%8.8X \n", (int)aMechanisms[i]);
				printf(" Min key size:      0x%8.8X \n", (int)mechInfo.ulMinKeySize);
				printf(" Max key size:      0x%8.8X \n", (int)mechInfo.ulMaxKeySize);
				printf(" Mechanism flags:   0x%8.8X \n", (int)mechInfo.flags);
			}
		}
		break;
	}

	if (aMechanisms)
	{
		free(aMechanisms);
		aMechanisms = NULL_PTR;
	}
	return *prv == CKR_OK;
}

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                            // Хэндл загруженной библиотеки PKCS#11

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;         // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;     // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                      // Указатель на массив идентификаторов всех доступных слотов
	CK_ULONG ulSlotCount = 0;                              // Количество идентификаторов всех доступных слотов в массиве

	CK_SLOT_ID_PTR aSlotWithToken = NULL_PTR;              // Указатель на массив идентификаторов слотов с подключенными токенами
	CK_ULONG ulSlotWithTokenCount = 0;                     // Количество идентификаторов слотов с подключенными токенами в массиве

	CK_INFO libraryInfo;                                   // Структура данных типа CK_INFO с общей информацией о библиотеке

	CK_RV rv = CKR_OK;                                     // Вспомогательная переменная для хранения кода возврата

	DWORD i = 0;                                           // Вспомогательная переменная-счетчик для циклов

	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Загрузить библиотеку.                                        *
		**********************************************************************/
		printf("Loading library %s ", PKCS11ECP_LIBRARY_NAME);   // или PKCS11ECP_LIBRARY_NAME
		hModule = LoadLibrary(PKCS11ECP_LIBRARY_NAME);
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
		* Шаг 3: Получить структуру с указателями на функции.                 *
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
		* Шаг 4: Инициализировать библиотеку.                                 *
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
		* Шаг 5: Получить информацию о библиотеке.                            *
		**********************************************************************/
		printf("\nC_GetInfo ");
		memset(&libraryInfo,
		       0,
		       sizeof(CK_INFO));

		rv = pFunctionList->C_GetInfo(&libraryInfo);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 6: Распечатать информацию о библиотеке.                         *
		**********************************************************************/
		printf("Printing library info: \n");
		printf(" PKCS#11 Ver:         %d.%d \n", (&libraryInfo)->cryptokiVersion.major, (&libraryInfo)->cryptokiVersion.minor);
		printf(" Manufacturer:        %.*s \n", (int)sizeof((&libraryInfo)->manufacturerID), (&libraryInfo)->manufacturerID);
		printf(" Flags:               0x%8.8X \n", (int)(&libraryInfo)->flags);
		printf(" Library description: %.*s \n\n", (int)sizeof((&libraryInfo)->libraryDescription), (&libraryInfo)->libraryDescription);

		/**********************************************************************
		* Шаг 7: Определить количество всех доступных слотов.                 *
		**********************************************************************/
		printf("Getting number of all slots");
		rv = pFunctionList->C_GetSlotList(CK_FALSE,
		                                  NULL_PTR,
		                                  &ulSlotCount);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
		memset(aSlots,
		       0,
		       (ulSlotCount * sizeof(CK_SLOT_ID)));

		/**********************************************************************
		* Шаг 8: Получить список всех доступных слотов.                       *
		**********************************************************************/
		printf("Getting all slots list");
		rv = pFunctionList->C_GetSlotList(CK_FALSE,
		                                  aSlots,
		                                  &ulSlotCount);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Шаг 9: Определить количество слотов с подключенными токенами.       *
		**********************************************************************/
		printf("Getting number of connected slots");
		rv = pFunctionList->C_GetSlotList(CK_TRUE,
		                                  NULL_PTR,
		                                  &ulSlotWithTokenCount);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		aSlotWithToken = (CK_SLOT_ID*)malloc(ulSlotWithTokenCount * sizeof(CK_SLOT_ID));
		memset(aSlotWithToken,
		       0,
		       (ulSlotWithTokenCount * sizeof(CK_SLOT_ID)));

		/**********************************************************************
		* Шаг 10: Получить список слотов с подключенными токенами.             *
		**********************************************************************/
		printf("Getting list of connected slots");
		rv = pFunctionList->C_GetSlotList(CK_TRUE,
		                                  aSlotWithToken,
		                                  &ulSlotWithTokenCount);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		printf("\nNumber of all slots:       0x%8.8X \n", (int)ulSlotCount);
		printf("Number of connected slots: 0x%8.8X \n", (int)ulSlotWithTokenCount);

		/************************************************************************
		* Шаг 11: Распечатать инфомацию:                                        *
		*         - о слотах;                                                   *
		*         - о подключенных токенах;                                     *
		*         - о поддерживаемых механизмах.                                *
		************************************************************************/
		for (i = 0;
		     i < ulSlotCount;
		     i++)
		{

			printf("\nSlot number: 0x%8.8X\n", (int)i);
			PrintSlotInfo(pFunctionList,
			              aSlots[i],
			              &rv);
		}
		break;
	}

	if (aSlotWithToken)
	{
		free(aSlotWithToken);
		aSlotWithToken = NULL_PTR;
	}
	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	/**********************************************************************
	* Шаг 12: Деинициализировать библиотеку.                              *
	**********************************************************************/
	if (pFunctionList)
	{
		pFunctionList->C_Finalize(NULL_PTR);
		pFunctionList = NULL_PTR;
	}

	/**********************************************************************
	* Шаг 13: Выгрузить библиотеку из памяти.                             *
	**********************************************************************/
	if (hModule)
	{
		FreeLibrary(hModule);
		hModule = NULL_PTR;
	}

	if (rv != CKR_OK)
		printf("\nSome error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else
		printf("\nTest has been completed succesfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}

