#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <Common.h>

using namespace v8;

static void LogCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
    if (args.Length() < 1) return;
    HandleScope scope(args.GetIsolate());
    Handle<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
}

void Method(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  args.GetReturnValue().Set(String::NewFromUtf8(isolate, "world 2"));
}

//
// Метод инициализации
//
void init(Handle<Object> target) {

    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    HMODULE hModule = NULL_PTR;                            // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                 // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;         // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;     // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                      // Указатель на массив идентификаторов всех доступных слотов
	CK_ULONG ulSlotCount = 0;                              // Количество идентификаторов всех доступных слотов в массиве

	CK_RV rv = CKR_OK;                                     // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                 // Вспомогательная переменная для хранения кода возврата

    hModule = LoadLibrary(PKCS11_LIBRARY_NAME);

    if(hModule == NULL_PTR) {
        target->Set(String::NewFromUtf8(isolate, "hModule"), String::NewFromUtf8(isolate, "False"));
    } else {
        target->Set(String::NewFromUtf8(isolate, "hModule"), String::NewFromUtf8(isolate, "True"));
    }

    NODE_SET_METHOD(target, "hello", Method);
}

//
// Инициализация модуля и вызов метода init
//
NODE_MODULE(binding, init);
