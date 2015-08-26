#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <Common.h>
#include <string>

using namespace v8;

bool              bInitialize = false; // Флаг инициализации библиотеки PKCS#11 fnInitialize()

HMODULE           hModule  = NULL_PTR; // Хэндл загруженной библиотеки PKCS#11
CK_SESSION_HANDLE hSession = NULL_PTR; // Хэндл открытой сессии

CK_FUNCTION_LIST_PTR pFunctionList     = NULL_PTR; // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
CK_C_GetFunctionList pfGetFunctionList = NULL_PTR; // Указатель на функцию C_GetFunctionList

CK_SLOT_ID_PTR aSlots      = NULL_PTR; // Указатель на массив идентификаторов всех доступных слотов
CK_ULONG       ulSlotCount = 0;        // Количество идентификаторов всех доступных слотов в массиве

CK_SLOT_INFO  slotInfo;  // Структура данных типа CK_SLOT_INFO с информацией о слоте
CK_TOKEN_INFO tokenInfo; // Структура данных типа CK_TOKEN_INFO с информацией о токене

CK_RV rv     = CKR_OK; // Вспомогательная переменная для хранения кода возврата
CK_RV rvTemp = CKR_OK; // Вспомогательная переменная для хранения кода возврата

static void LogCallback(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1) return;
    HandleScope scope(args.GetIsolate());
    Handle<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
}

void Method(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  args.GetReturnValue().Set(String::NewFromUtf8(isolate, "world"));
}

//
// Инициализация библиотеки rtPKCS11ECP.dll
// Метод вызывается в методе init
//
void fnInitialize(const FunctionCallbackInfo<Value>& args) {
    // Шаг 1: Загрузить библиотеку.
    hModule = LoadLibrary("rtPKCS11ECP.dll");

    // Шаг 2: Получить адрес функции запроса структуры с указателями на функции.
    if (hModule != NULL_PTR) {
        pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
    }

    // Шаг 3: Получить структуру с указателями на функции.
    if (pfGetFunctionList != NULL_PTR) {
        rv = pfGetFunctionList(&pFunctionList);
    }

    // Шаг 4: Инициализировать библиотеку.
    if(rv == CKR_OK) {
        rv = pFunctionList->C_Initialize(NULL_PTR);
    }

    // Шаг 5: Установить флаг isDLL = true.
    if(rv == CKR_OK) {
        bInitialize = true;
    }

    args.GetReturnValue().Set(bInitialize);
}
void isInitialize(const FunctionCallbackInfo<Value>& args) {
    args.GetReturnValue().Set(bInitialize);
}

//
// C_GetSlotList()
//
void fnGetSlotList(const FunctionCallbackInfo<Value>& args) {
    int err = 0;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
    if (rv == CKR_OK) {
        aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
		memset(aSlots, 0, (ulSlotCount * sizeof(CK_SLOT_ID)));
        rv = pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulSlotCount);
        if (rv == CKR_OK) {
            args.GetReturnValue().Set((int)ulSlotCount);
        } else {
            err = (int)rv * -1;
        }
    } else {
        err = (int)rv * -1;
    }

    if(err != 0) {
        args.GetReturnValue().Set(err);
    }

}

//
// C_GetSlotInfo
//
void fnGetSlotInfo(const FunctionCallbackInfo<Value>& args) {

    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int slot = (int)args[0]->NumberValue();

    rv = pFunctionList->C_GetSlotInfo(slot, &slotInfo);

    if (rv == CKR_OK) {
        args.GetReturnValue().Set(String::NewFromUtf8(isolate, (const char *)slotInfo.slotDescription));
    } else {
        if(rv == CKR_ARGUMENTS_BAD) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_ARGUMENTS_BAD"));
        if(rv == CKR_CRYPTOKI_NOT_INITIALIZED) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_CRYPTOKI_NOT_INITIALIZED"));
        if(rv == CKR_DEVICE_ERROR) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_DEVICE_ERROR"));
        if(rv == CKR_FUNCTION_FAILED) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_FUNCTION_FAILED"));
        if(rv == CKR_GENERAL_ERROR) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_GENERAL_ERROR"));
        if(rv == CKR_HOST_MEMORY) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_HOST_MEMORY"));
        if(rv == CKR_SLOT_ID_INVALID) args.GetReturnValue().Set(String::NewFromUtf8(isolate, "CKR_SLOT_ID_INVALID"));
    }

}

//
// Метод инициализации модуля
//
void init(Handle<Object> exports) {
    // Регистрация методов
    NODE_SET_METHOD(exports, "fnInitialize", fnInitialize);
    NODE_SET_METHOD(exports, "isInitialize", isInitialize);

    NODE_SET_METHOD(exports, "fnGetSlotList", fnGetSlotList);

    NODE_SET_METHOD(exports, "fnGetSlotInfo", fnGetSlotInfo);
}

//
// Инициализация модуля и вызов метода init
//
NODE_MODULE(rutoken, init);
