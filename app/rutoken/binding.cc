#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <Common.h>

using namespace v8;

bool              bIsDLL    = false; // Флаг инициализации библиотеки PKCS#11

HMODULE           hModule  = NULL_PTR; // Хэндл загруженной библиотеки PKCS#11
CK_SESSION_HANDLE hSession = NULL_PTR; // Хэндл открытой сессии

CK_FUNCTION_LIST_PTR pFunctionList     = NULL_PTR; // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
CK_C_GetFunctionList pfGetFunctionList = NULL_PTR; // Указатель на функцию C_GetFunctionList

CK_SLOT_ID_PTR aSlots      = NULL_PTR; // Указатель на массив идентификаторов всех доступных слотов
CK_ULONG       ulSlotCount = 0;        // Количество идентификаторов всех доступных слотов в массиве

CK_RV rv     = CKR_OK;                 // Вспомогательная переменная для хранения кода возврата
CK_RV rvTemp = CKR_OK;                 // Вспомогательная переменная для хранения кода возврата

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
void initDLL() {
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
        bIsDLL = true;
    }
}

//
// Проверка загрузки библиотеки ее инициализация
//
void isDLL(const FunctionCallbackInfo<Value>& args) {
    args.GetReturnValue().Set(bIsDLL);
}

//
// Метод инициализации модуля
//
void init(Handle<Object> target) {

    //Isolate* isolate = Isolate::GetCurrent();
    //HandleScope scope(isolate);
    initDLL();

    // Регистрация методов
    NODE_SET_METHOD(target, "isDLL", isDLL);
}

//
// Инициализация модуля и вызов метода init
//
NODE_MODULE(binding, init);
