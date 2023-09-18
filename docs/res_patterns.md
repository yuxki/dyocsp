# Response patterns
This is the response pattern list of DyOCSP. " - " indicates unrelated condition.

|Request|Issuers\*1|Certificate status in DB\*2|Requested serial number matched cache|Request time is before nextUpdate|Response status|Certificate status in response|
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
|Malformed|-|-|-|-|malformedRequest|-|
|Formed|Different|-|-|-|unauthorized|-|
|Formed|Same|E|-|-|unauthorized|-|
|Formed|Same|S|-|-|unauthorized|-|
|Formed|Same|V|no|-|unauthorized|-|
|Formed|Same|R|no|-|unauthorized|-|
|Formed|Same|V|yes|no|unauthorized|-|
|Formed|Same|R|yes|no|unauthorized|-|
|Formed|Same|V|yes|yes|successful|good|
|Formed|Same|R|yes|yes|successful|revoked|

\*1: The issuer of the requested certificate and the issuer of the responder.\
\*2: Expired, Suspended, Valid, Revoked
