/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд получения информации о событиях в слотах:         *
*  - инициализация библиотеки;                                           *
*  - проверка события в каком-либо слоте (без блокировки                 *
*    выполнения потока приложения);                                      *
*  - ожидание события потоком в каком-либо слоте (с блокировкой          *
*    выполнения потока приложения).                                      *
*------------------------------------------------------------------------*
* Данный пример является самодостаточным из серии примеров работы        *
* с библиотекой PKCS#11                                                  *
*************************************************************************/

#include "Common.h"


/* Количество потоков, одновременно ожидающих события в каком-либо слоте*/
#define MONITORING_THREADS_NUMBER    1

/************************************************************************
* Структура данных, содержащая параметры работы                         *
* для функции ожидания событий в слотах                                 *
************************************************************************/
typedef struct _MONITORING_THREADS_PARAMS
{
	CK_FUNCTION_LIST_PTR m_pFunctionList;
	CK_FLAGS m_flags;
	DWORD m_dwThread_Number;
} MONITORING_THREADS_PARAMS, * PMONITORING_THREADS_PARAMS;

/************************************************************************
* Запустить поток, ожидающий событие в слоте.                           *
* До наступления события выполнение потока заблокировано.               *
************************************************************************/
void Monitoring_Slots(IN void* param  // Указатель на структуру данных типа MONITORING_THREADS_PARAMS с параметрами для запуска потоков
                      )
{
	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;        // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST

	CK_SLOT_ID slotID = 0xFFFFFFFF;                       // Идентификатор слота, в котором произошло событие
	CK_SLOT_INFO slotInfo;                                // Структура данных типа CK_SLOT_INFO с информацией о слоте

	CK_FLAGS ckFlags = 0;                                 // Вспомогательная переменная для хранения флагов, передаваемых в функцию C_ cWaitForSlotEvent
	DWORD dwThreadNumber = 0;                             // Вспомогательная переменная для хранения порядкового номера запущенного потока

	CK_RV rv = CKR_OK;                                    // Вспомогательная переменная для хранения кода возврата

	/************************************************************************
	* Получить из структуры данных типа MONITORING_THREADS_PARAMS           *
	* параметры для дальнейшей работы                                       *
	************************************************************************/
	PMONITORING_THREADS_PARAMS pMonitoring_Threads_Param = (PMONITORING_THREADS_PARAMS)param;

	pFunctionList = pMonitoring_Threads_Param->m_pFunctionList;
	ckFlags = pMonitoring_Threads_Param->m_flags;
	dwThreadNumber = pMonitoring_Threads_Param->m_dwThread_Number;

	while (TRUE)
	{
		/************************************************************************
		* Ожидать событие в некотором слоте, режим работы функции               *
		* C_WaitForSlotEvent зависит от значения флагов ckFlags                 *
		************************************************************************/
		slotID = 0xFFFFFFFF;
		rv = pFunctionList->C_WaitForSlotEvent(ckFlags,
		                                       &slotID,
		                                       NULL_PTR);

		if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
			printf("Work with PKCS#11 has been finished.\n");
			break;
		}
		if (rv == CKR_NO_EVENT)
		{
			printf(" -> Failed \n"
			       "No more slot events...\n");
			break;
		}
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}

		memset(&slotInfo,
		       0,
		       sizeof(CK_SLOT_INFO));

		/************************************************************************
		* Получить информацию о слоте                                           *
		************************************************************************/
		rv = pFunctionList->C_GetSlotInfo(slotID,
		                                  &slotInfo);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}

		/************************************************************************
		* Распечать информацию о номере потока и событии в слоте                *
		************************************************************************/
		printf("\n Monitoring thread: 0x%8.8x \n", (int)dwThreadNumber);
		printf("  Slot ID:          0x%8.8x \n", (int)slotID);
		if (slotInfo.flags & CKF_TOKEN_PRESENT)
			printf("  Token has been attached!\n");
		else
			printf("  Token has been detached!\n");
	}
	printf("Exiting from thread: 0x%8.8x \n\n", (int)dwThreadNumber);
}

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                              // Хэндл загруженной библиотеки PKCS#11

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;           // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;       // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID slotID = 0xFFFFFFFF;                          // Идентификатор слота, в котором произошло событие
	CK_SLOT_INFO slotInfo;                                   // Структура данных типа CK_SLOT_INFO с информацией о слоте

	DWORD i = 0;                                             // Вспомогательная переменная. Счетчик цикла
	CK_RV rv = CKR_OK;                                       // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                   // Вспомогательная переменная для хранения кода возврата

	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Загрузить библиотеку                                         *
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
		* Шаг 2: Получить адрес функции запроса структуры                     *
		*        с указателями на функции                                     *
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

		printf("\nPlease attach or detach Rutoken and press Enter...\n");
		getchar();

		i = 1;
		while (TRUE)
		{
			printf("Events counter: 0x%8.8x \n", (int)i);

			/**********************************************************************
			* Шаг 5: Получить все события в слотах                                *
			*        (не блокируя поток, используем флаг CKF_DONT_BLOCK ).        *
			**********************************************************************/
			printf("C_WaitForSlotEvent");
			rv = pFunctionList->C_WaitForSlotEvent(CKF_DONT_BLOCK,
			                                       &slotID,
			                                       NULL_PTR);
			if (rv == CKR_NO_EVENT)
			{
				printf(" -> OK\n");
				printf("No more slots events.\n");
				break;
			}
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* Шаг 6: Получить и распечатать информацию о слоте                    *
			**********************************************************************/
			memset(&slotInfo,
			       0,
			       sizeof(CK_SLOT_INFO));

			printf("C_GetSlotInfo");
			rv = pFunctionList->C_GetSlotInfo(slotID,
			                                  &slotInfo);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			printf(" Slot ID:           0x%8.8X \n", (int)slotID);
			printf(" Slot description:  %.*s \n", (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription);
			printf(" Manufacturer:      %.*s \n", (int)sizeof(slotInfo.manufacturerID), slotInfo.manufacturerID);
			printf(" Flags:             0x%8.8X \n", (int)slotInfo.flags);
			printf(" Hardware Ver:      %d.%d \n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
			printf(" Firmware Ver:      %d.%d \n\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);

			i++;
		}

		if ((rv != CKR_NO_EVENT) && (rv != CKR_OK))
			break;

		/**********************************************************************
		* Шаг 7: Запустить поток, ожидающих событие в каком-либо слоте.       *
		*        До наступления события выполнение запущенного потока         *
		*        заблокировано. Первое же событие разблокирует выполнение     *
		*        ожидающего потока.                                           *
		**********************************************************************/
		while (TRUE)
		{
			MONITORING_THREADS_PARAMS aThreads_With_Blocking[MONITORING_THREADS_NUMBER];
			uintptr_t aThreads[MONITORING_THREADS_NUMBER];

			for (i = 0;
			     i < MONITORING_THREADS_NUMBER;
			     i++)
			{
				printf("Starting monitoring thread number 0x%8.8X \n", (int)i);

				memset(&aThreads_With_Blocking[i],
				       0,
				       sizeof(MONITORING_THREADS_PARAMS));

				aThreads_With_Blocking[i].m_pFunctionList = pFunctionList;
				aThreads_With_Blocking[i].m_flags = 0;
				aThreads_With_Blocking[i].m_dwThread_Number = i;

				aThreads[i] = CreateProc(&aThreads[i], NULL_PTR, &Monitoring_Slots, &aThreads_With_Blocking[i]);
			}

			printf("\n\nPlease attach or detach Rutoken or press Enter to exit.\n");

			getchar();
			break;
		}
		break;
	}

	/**********************************************************************
	* Шаг 8: Деинициализировать библиотеку.                               *
	**********************************************************************/

	if (pFunctionList)
	{
		rvTemp = pFunctionList->C_Finalize(NULL_PTR);
		if (rvTemp != CKR_OK)
			printf("C_Finalize -> Failed\n");
		else
			printf("C_Finalize -> OK\n");
		pFunctionList = NULL_PTR;
	}

	/**********************************************************************
	* Шаг 9: Выгрузить библиотеку из памяти.                              *
	**********************************************************************/
	if (hModule)
	{
		printf("Unloading");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n\n");
		else
			printf(" -> OK\n\n");
		hModule = NULL_PTR;
	}

	if ((rv != CKR_OK) && (rv != CKR_NO_EVENT))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}

