# RutokenJS

[NW.js addons](https://github.com/nwjs/nw.js/wiki/Using-Node-modules#3rd-party-modules-with-cc-addons) for [Rutoken](http://www.rutoken.ru/)

[Функции PKCS #11, поддерживаемые устройствами Рутокен](http://developer.rutoken.ru/pages/viewpage.action?pageId=3178534)

### Сборка
```
nw-gyp configure --target=0.12.3
nw-gyp build
```

### API RutokenJS

error initialize()

bool isInitialize()

error finalize()

error|int countSlot()

error|object getLibInfo()

error|callback getSlotInfo(int slot, function(data))

error|callback getTokenInfo(int slot, function(data))

error|callback getMechanismList(int slot, function(data))

login()

random()

error initToken(int slot, string pin, string label)
