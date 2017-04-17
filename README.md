php secret
====================

### work flow

* server generate a public key give to client
* client user PBK encode data
```php
[
    "data"=> ...
    "client_public_key"=> (client use that PVK generate's PBK)
    "app_id"=> ...
    "type"=> [delay|immediately]
]
```

* server get data and decode that get data
* check type
    * delay -> push to queue
    * immediately -> response data to client
