\W10\
\SA6:10:Select screen PE01 \
M_DNL_SCREEN_REQUEST|PE01|1|0|
M_SCR_GET_SEC_KEYS|PE01|
M_SCR_RUN_SCREEN_INIT|PE01||0|
\TA6:\
\SA7:10:Look up an employee by number on PE01 \
M_SCR_RETRIEVE|PE01|
M_SCR_FIELD_RESPONSE|21|
M_SCR_FIELD_RESPONSE|101000|
\TA7:\
\SAG:10:Save details \
M_SCR_SAVE|PE01|
M_SCR_FIELD_RESPONSE|AA101000A|
M_SCR_FIELD_RESPONSE|M|
M_SCR_FIELD_RESPONSE|MR|
M_SCR_SET_CONFIRM_UPDATES|256|
M_SCR_FIELD_RESPONSE|101000|
M_SCR_FIELD_RESPONSE||
M_SCR_FIELD_RESPONSE|Person 101000|
M_SCR_FIELD_RESPONSE|21|
M_SCR_FIELD_RESPONSE|101000|
M_SCR_FIELD_RESPONSE||
M_SCR_FIELD_RESPONSE||
M_SCR_FIELD_RESPONSE|Wemcott|
M_SCR_FIELD_RESPONSE|Old Vyne Lane|
M_SCR_FIELD_RESPONSE|West Heath|
M_SCR_FIELD_RESPONSE|Tadley|
M_SCR_FIELD_RESPONSE|RG26 5LF|
M_SCR_FIELD_RESPONSE|01256-999999|
\TAG:\
\SAI:10:Clear screen PE01 \
M_SCR_CLEAR_ALL_FIELDS|PE01|
\TAI:\
