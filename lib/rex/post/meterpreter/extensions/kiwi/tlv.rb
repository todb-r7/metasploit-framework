# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Kiwi

TLV_TYPE_KIWI_PWD_ID               = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 1)
TLV_TYPE_KIWI_PWD_RESULT           = TLV_META_TYPE_GROUP  | (TLV_EXTENSIONS + 2)
TLV_TYPE_KIWI_PWD_USERNAME         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 3)
TLV_TYPE_KIWI_PWD_DOMAIN           = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 4)
TLV_TYPE_KIWI_PWD_PASSWORD         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 5)
TLV_TYPE_KIWI_PWD_AUTH_HI          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 6)
TLV_TYPE_KIWI_PWD_AUTH_LO          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 7)
TLV_TYPE_KIWI_PWD_LMHASH           = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 8)
TLV_TYPE_KIWI_PWD_NTLMHASH         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9)

TLV_TYPE_KIWI_GOLD_USER            = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 10)
TLV_TYPE_KIWI_GOLD_DOMAIN          = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 11)
TLV_TYPE_KIWI_GOLD_SID             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 12)
TLV_TYPE_KIWI_GOLD_TGT             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 13)
TLV_TYPE_KIWI_GOLD_TICKET          = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 14)

TLV_TYPE_KIWI_LSA_VER_MAJ          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 15)
TLV_TYPE_KIWI_LSA_VER_MIN          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 16)
TLV_TYPE_KIWI_LSA_COMPNAME         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 17)
TLV_TYPE_KIWI_LSA_SYSKEY           = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 18)
TLV_TYPE_KIWI_LSA_KEYCOUNT         = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 19)
TLV_TYPE_KIWI_LSA_KEYID            = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 20)
TLV_TYPE_KIWI_LSA_KEYIDX           = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 21)
TLV_TYPE_KIWI_LSA_KEYVALUE         = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 22)
TLV_TYPE_KIWI_LSA_NT6KEY           = TLV_META_TYPE_GROUP  | (TLV_EXTENSIONS + 23)
TLV_TYPE_KIWI_LSA_NT5KEY           = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 24)

TLV_TYPE_KIWI_LSA_SECRET           = TLV_META_TYPE_GROUP  | (TLV_EXTENSIONS + 25)
TLV_TYPE_KIWI_LSA_SECRET_NAME      = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 26)
TLV_TYPE_KIWI_LSA_SECRET_SERV      = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 27)
TLV_TYPE_KIWI_LSA_SECRET_NTLM      = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 28)
TLV_TYPE_KIWI_LSA_SECRET_CURR      = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 29)
TLV_TYPE_KIWI_LSA_SECRET_CURR_RAW  = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 30)
TLV_TYPE_KIWI_LSA_SECRET_OLD       = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 31)
TLV_TYPE_KIWI_LSA_SECRET_OLD_RAW   = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 32)

TLV_TYPE_KIWI_LSA_SAM              = TLV_META_TYPE_GROUP  | (TLV_EXTENSIONS + 33)
TLV_TYPE_KIWI_LSA_SAM_RID          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 34)
TLV_TYPE_KIWI_LSA_SAM_USER         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 35)
TLV_TYPE_KIWI_LSA_SAM_LMHASH       = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 36)
TLV_TYPE_KIWI_LSA_SAM_NTLMHASH     = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 37)

end
end
end
end
end
