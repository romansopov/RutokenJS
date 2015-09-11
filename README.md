# RutokenJS

[NW.js addons](https://github.com/nwjs/nw.js/wiki/Using-Node-modules#3rd-party-modules-with-cc-addons) for [Rutoken](http://www.rutoken.ru/)

[Функции PKCS #11, поддерживаемые устройствами Рутокен](http://developer.rutoken.ru/pages/viewpage.action?pageId=3178534)

### Сборка
```
nw-gyp configure --target=0.12.3
nw-gyp build
```

### API RutokenJS

*CKR* **initialize**()

*bool* **isInitialize**()

*CKR* **finalize**()

*object* **countSlot**()

*object* **getLibInfo**()

*object* **getSlotInfo**(int slot)

*object* **getTokenInfo**(int slot)

*object* **getMechanismList**(int slot)

*object* **getObjectList**()

*CKR* **login**(int slot, string pin)

*CKR* **loguot**()

*object* **random**(int size)

*CKR* **initToken**(int slot)

*CKR* **openSession**()

*CKR* **closeSession**()

*CKR* **closeAllSessions**()

*object* **getSessionInfo**()

*CKR* **getOperationState**()

*CKR* **setOperationState**()

