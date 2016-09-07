/*
 * Scan a snoop file and pull out the Delphi elements (hopefully). 
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include "hashlib.h"
#include "e2conv.h"
#include "e2net.h"
#include "dfsdrive.h"
/*
 * Delphi message Control
 */
struct dfs_mess dfs_mess[] = {
{ 0,"M_EMPTY"},
{ 248,"M_UNKNOWN_248",0, 1 },
{ 250,"M_UNKNOWN_250",0, 1 },
{ 255,"M_UNKNOWN_255",0, 1 },
{ 256,"M_GEN_ERROR_MESSAGE", "1S201"},
{ 257,"M_GEN_STATUS_MESSAGE", "1S201"},
{ 258,"M_GEN_GET_TYPE_OF_ID_X", "1S6"},
{ 259,"M_GEN_ID_X_IS_TYPE_Y", "1I2"},
{ 523,"M_LOG_VERSION_RESPONSE", "1I4 1I2 1S2", 1},
{ 522,"M_LOG_VERSION_CHECK", "1I1", 1},
{ 520,"M_LOG_AUTH", "1I1", 1},
{ 521,"M_LOG_AUTH_RESPONSE", "1S13 1I1", 1},
{ 512,"M_LOG_LOGIN", "1S13 1S7 1S9", 1},
{ 513,"M_LOG_LOGIN_RESPONSE", "1I1 1S17 1S11 1I1 1I1 1I1 1I1 1I1 1I1 1I1 1I1 1I1 1I1 1I1", 1},
{ 514,"M_LOG_LOGOUT", "1I1"},
{ 515,"M_LOG_NEW_PASSWORD", "1S9"},
{ 517,"M_LOG_INIT", "1I1", 1},
{ 518,"M_LOG_INIT_RESPONSE", "1I1", 1},
{ 519,"M_LOG_SHUTDOWN", "1I1"},
{ 524,"M_LOG_VERSION_OF_CLIENT", "1I2"},
{ 768,"M_DNL_MENU_REQUEST", "1S5", 1},
{ 769,"M_DNL_OBJECT_ERROR", "1I1", 1},
{ 770,"M_DNL_MENU_RESPONSE", "1S5 1S51 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S5 1S5 1S5 1S5 1S5 1S5 1S5 1S5 1S5 1S11 1S11 1S11 1I1", 1},
{ 771,"M_DNL_SCREEN_REQUEST", "1S5 1I1 1I1", 1},
{ 772,"M_DNL_SCREEN_HEADER", "1I2 1I2 1I2 1I2 1I2 1I2 1S5 1S51 1I1 1S9 1S11 1S11 1S9 1S11 1S11 1S9 1S11 1S11 1S9 1S11 1S11 1S9 1S11 1S11 1S9 1S11 1S11 1S13 1S13 1I1 1S11 1S11 1S11 1I1"},
{ 788,"M_DNL_WINDOW_POSITION", "1I2 1I2 1I2 1I2"},
{ 773,"M_DNL_SCREEN_FIELD", "1I2 1I2 1I2 1I2 1I2 1I2 1I2 1I2 1I2 1I2 1I2 1I2 1S81 1S21 1I1 1I1 1I1 1S18 1I1 1S17 1S17 1S81 1S91 1I1 1S5 1I1 1I1 1I1 1I1 1I1 1S391 1S11 1I1"},
{ 774,"M_DNL_SCREEN_OVER", "1I1", 1},
{ 775,"M_DNL_SCREEN_HELP_REQUEST", "1S5", 1},
{ 780,"M_DNL_SCREEN_HELP_EXISTS", "1S5", 1},
{ 776,"M_DNL_SCREEN_HELP_RESPONSE", "1I4", 1},
{ 777,"M_DNL_SCREEN_HELP_ABORT", "1I1"},
{ 778,"M_DNL_SCREEN_HELP_DATA", "1S1024"},
{ 781,"M_DNL_SCREEN_HELP_EXISTS_RESPONSE", "1I1", 1},
{ 782,"M_DNL_SCREEN_MENU_LIST_REQUEST", "1S1024"},
{ 783,"M_DNL_SCREEN_MENU_LIST", "1I2 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1S5 1S51 1I1 1I1"},
{ 785,"M_DNL_QUERY_VARIABLES_START", "1I2 1S9 1I1"},
{ 786,"M_DNL_QUERY_VARIABLES_DATA", "1I2 1S3 1S51"},
{ 787,"M_DNL_QUERY_VARIABLES_RESPONSE", "1I1 1S703"},
{ 1024,"M_SEC_DOWNLOAD", "1I1", 1},
{ 1025,"M_SEC_DETAILS", "1I4 1I4 1I4 1I4 1S7 1S7 1S9 1I1 1S21 1S7 1I1 1I1 1I1 1I1 1I1 1S3", 1},
{ 1026,"M_SEC_SCREENS", "1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1"},
{ 1027,"M_SEC_MENUS", "1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1 1S5 1I1"},
{ 1028,"M_SEC_EXEC_ADL", "1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1 1S9 1I1"},
{ 1029,"M_SEC_KEY_SEC", "1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9 1S13 1S4 1S9"},
{ 1335,"M_SCR_DISPLAY_AT", "1I2 1I2 1S81 1I1"},
{ 1280,"M_SCR_RUNNING", "1S5 1I1 1S11"},
{ 1281,"M_SCR_RUNNING_RESPONSE", "1S5 1I1 1S11"},
{ 1282,"M_SCR_NOT_RUNNING", "1S5"},
{ 1283,"M_SCR_RETRIEVE", "1S5", 1},
{ 1284,"M_SCR_RETRIEVE_OVER", "1I1", 1},
{ 1285,"M_SCR_GET_SIMPLE_FIELD", "1S5 1S21", 1},
{ 1286,"M_SCR_FIELD_RESPONSE", "1S1001", 1, 1},
{ 1287,"M_SCR_SET_SIMPLE_FIELD", "1S5 1S21 1S1001"},
{ 1288,"M_SCR_TABLE_DATA_REQUEST", "1S5"},
{ 1289,"M_SCR_TABLE_DATA_START_1", "1I2"},
{ 1290,"M_SCR_TABLE_DATA_START_2", "1I2"},
{ 1337,"M_SCR_GET_TABLE_LINE", "1S5"},
{ 1336,"M_SCR_RETURN_TABLE_LINE", "1I2"},
{ 1291,"M_SCR_TABLE_ROW_DATA", "1I2 1I2 1S1001 1I1"},
{ 1292,"M_SCR_TABLE_ROW_DATA1", "1I2 1I2 1S1001 1I1"},
{ 1293,"M_SCR_TABLE_ROW_DATA2", "1I2 1I2 1S1001 1I1"},
{ 1294,"M_SCR_TABLE_END", "1S5"},
{ 1295,"M_SCR_SAVE", "1S5", 1},
{ 1296,"M_SCR_SAVE_OVER", "1I1", 1},
{ 1297,"M_SCR_GET_SEC_KEYS", "1S5",1},
{ 1298,"M_SCR_SEC_KEYS", "1I2 1S5 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1 1S21 1I1 1I1 1I1", 1},
{ 1299,"M_SCR_PAGE_REQUEST", "1S5 1S21 1I1"},
{ 1302,"M_SCR_SET_FEATURE", "1I1 1I1"},
{ 1303,"M_SCR_RUN_SCREEN_INIT", "1S5 1S5 1I1", 1},
{ 1304,"M_SCR_INIT_OVER", "1I1", 1},
{ 1305,"M_SCR_RUN_SCREEN_CLOSE", "1S5 1S5 1I1 1I1", 1},
{ 1306,"M_SCR_SCREEN_CLOSE_OVER", "1I1", 1},
{ 1307,"M_SCR_PARENT_SERVER_MODE", "1I1"},
{ 1308,"M_SCR_CURRENT_SERVER_MODE", "1I1"},
{ 1309,"M_SCR_RUN_SCREEN_PASSBACK_1", "1S5 1S5 1I1 1I1 1S21 1S21", 1},
{ 1310,"M_SCR_RUN_SCREEN_PASSBACK_OVER_1", "1I1", 1},
{ 1311,"M_SCR_RUN_SCREEN_PASSBACK_2", "1S5 1S5", 1},
{ 1312,"M_SCR_RUN_SCREEN_PASSBACK_OVER_2", "1I1", 1},
{ 1313,"M_SCR_NEXTSCREEN_ON_SAVE", "1S5"},
{ 1314,"M_SCR_RUN_DISPLAY_ADL", "1S5"},
{ 1316,"M_SCR_RUN_BATCH_PROGRAM", "1S5"},
{ 1318,"M_SCR_CURRENT_LINENO", "1I1"},
{ 1320,"M_SCR_KEYPRESS_RESPONSE", "1I1"},
{ 1321,"M_SCR_REPORT_OUTPUT_START", "1I4 1I4 1I2 1I2 1I2 1S9 1S41"},
{ 1322,"M_SCR_REPORT_OUTPUT_START_RESPONSE", "1I1"},
{ 1323,"M_SCR_REPORT_OUTPUT_DATA", "1S1024"},
{ 1325,"M_SCR_WP_START", "1S9 1S9 1I1"},
{ 1327,"M_SCR_DNAME_LIST", "1I2 1S45 1I1"},
{ 1328,"M_SCR_DNAME_DATA", "1S1024"},
{ 1329,"M_SCR_CLEAR_ALL_FIELDS", "1S5", 1},
{ 1330,"M_SCR_CLEAR_ALL_FIELDS_OVER", "1I1", 1},
{ 1331,"M_SCR_MSG_BOX", "1I2 1S201 1S5",1},
{ 1332,"M_SCR_MSG_BOX_RESP", "1I2", 1},
{ 1333,"M_SCR_GET_CONFIRM_UPDATES", "1I2", 1},
{ 1334,"M_SCR_SET_CONFIRM_UPDATES", "1I2", 1},
{ 65280, "M_DBG_RUNNING_SCREENS", "1S5 1S21"},
{ 65281, "M_DBG_SCREEN_INFO", "1S5 1S21"},
{ 65282, "M_DBG_ALL_FIELDS", "1S5 1S21"},
{ 65283, "M_DBG_FIELD_INFO", "1S5 1S21"},
{ -1 }};
/**************************************************************************
 * Deal with the Delphi TCP Stream
 *
 * Finally, having established the format of the data, and how the file
 * is constructed, output the seed scripts.
 */
void do_dfs_mess(len,p, out)
int len;
char *p;
int out;
{
/*
 * Assume whole message accumulated, process
 */
    if (len < 4 || ! dfsoutrec(stdout,p,IN))
        gen_handle(p,p+len,out);
    return;
}
void do_dfs (f, dir_flag)
struct frame_con * f;
int dir_flag;
{
    if (!dir_flag)
        do_dfs_mess(f->len[dir_flag], f->hold_buf[dir_flag], 1);
    return;
}
/*
 * - Routines that read or write one of the valid record types
 *   off a FILE.
 *
 * dfsinrec()
 *   - Sets up the record in a buffer that is passed to it
 *   - Strips trailing spaces
 *   - Returns the record type found
 *
 * dfsoutrec()
 *   - Fills a static buffer with the data that is passed to it
 *   - Strips trailing spaces
 *   - Returns 1 if successful, 0 if not.
 *
 ****************************************************************************
 * sicopy - change NULLs to spaces so that the input record can
 * be printed
 */
static void sicopy(out,in,rec_cnt)
char * out;
char * in;
int rec_cnt;
{
    register char * rin = in;
    register char * rout = out;
    while (*rin != '\0' && (rec_cnt-- > 0))
        *rout++ = *rin++;
    while (rec_cnt-- > 0)
       *rout++ = ' ';
    return;
}
/*
 * Hash function for Delphi message IDs
 */
unsigned mess_hh(w,modulo)
char * w;
int modulo;
{
long l = (long) w;
long maj = (l & 0xff00) >> 3;
    return(((int) ((l & 0xff) | maj)) & (modulo-1));
}
/*
 * Initialise the control structures for the message recognition
 */
void dfs_init()
{
struct dfs_mess *dmp;

    dfsdrive_base.idt = hash(256, mess_hh, icomp);
    dfsdrive_base.nmt = hash(256, string_hh, strcmp);
    for (dmp = &dfs_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(dfsdrive_base.idt, (char *) dmp->mess_id, (char *) dmp);
        insert(dfsdrive_base.nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    return;
}
/*********************************************************************
 * trail_null_strip - routine to shrink a record by the number of nulls on the
 * end.
 * - x is the pointer to the start of the string
 * - len is the maximum length
 * - the character at (x + len) must be a filler
 */
static int trail_null_strip(x,len)
char * x;
int len;
{
    register char * x1 = x + len -1;
    for (;*x1 == '\0' && x1 >= x;x1--);
    return x1 - x + 2;
}
/*********************************************************************
 * dfsinrec - read a record off the input stream
 * - read the record type
 * - return (char *) NULL if can't get the full thing
 * - strip any trailing space
 * - find out which record it is
 * - switch on the record type
 * - copy the record type
 * - read each field in turn into the buffer, null terminate it
 * - any error, return (char *) NULL
 * - if ultimately successful,
 * - return the record type originally read
 *
 * IN means that the data is in ASCII. 
 * OUT means that the data is in binary.
 *
 * The buffer contents are always binary.
 */
#ifdef AIX
int smart_read(f,buf,len)
int f;
char * buf;
int len;
{
int so_far = 0;
int r;
    do
    {
        r = read(f, buf, len);
        if (r <= 0)
            return r;
        so_far += r;
        len -= r;
        buf+=r;
    }
    while (len > 0);
    return so_far;
}
#endif
struct dfs_mess * dfsinrec(fp, b, in_out)
FILE * fp;
unsigned char * b;
enum direction_id in_out;
{
int eof_check;
static unsigned char buf[1048];
char * x;
int read_cnt;
int i;
static unsigned char data_header[4];
struct dfs_mess * dmp;
HIPT *h;
int mess_id;
int mess_len;
                            /* buffer to take the incoming record type */
    if ((fp == (FILE *) NULL) || b == (unsigned char *) NULL)
    {
        (void) fprintf(stderr,
               "Logic Error: dfsinrec() called with NULL parameter(s)\n");
        return NULL;
    }
    if (in_out == IN)
    {
/*
 * The record has already been read, and is in ASCII format in b. Convert it
 * in place.
 */
        if (dfsdrive_base.debug_level > 2)
            fputs(b,stderr);
        x = nextasc( b,'|','\\');
        if ((h = lookup(dfsdrive_base.nmt, x)) == (HIPT *) NULL)
        {
            (void) fputs( "Format failure: invalid message\n",stderr);
            (void) fprintf(stderr,"%64.64s\n",b);
            return NULL;
        }
        dmp = ((struct dfs_mess *) (h->body));
        if (dmp->mess_io != (struct iocon *) NULL)
        {
            x = b + strlen(dmp->mess_name) + 1;
            if (dfsdrive_base.debug_level > 2)
                fputs(x,stderr);
            mess_len = e2rec_conv(1, x, &buf[0], dmp->mess_io, '|');
            if (dfsdrive_base.debug_level > 2 && mess_len != dmp->mess_len)
                fprintf(stderr, "Expected: %d Actual: %d\n",
                     dmp->mess_len, mess_len);
           
            if (mess_len > 5
              && dmp->truncatable
              && (i = trail_null_strip(buf,mess_len)) < mess_len)
            {
                if (dfsdrive_base.debug_level > 2 && mess_len != i)
                    fprintf(stderr, "Truncated from %d to %d\n",
                      mess_len,i);
                mess_len = i;
            }
        }
        else
            mess_len = 0;
        mess_id = dmp->mess_id;
        b[0] = mess_id / 256;
        b[1] = mess_id % 256;
        b[2] = mess_len / 256;
        b[3] = mess_len % 256;
        if (mess_len > 0)
            memcpy(&b[4], &buf[0],mess_len);
    }
    else
    {
#ifdef AIX
        eof_check = smart_read(fileno(fp), data_header,sizeof(data_header));
#else
        eof_check = fread(data_header,sizeof(char),sizeof(data_header),fp);
#endif
        if (eof_check != sizeof(data_header))
        {
            if (eof_check)
            {
                (void) fputs("Format failure: data_header read failed\n",
                             stderr);
                if (eof_check > 0)
                {
                    gen_handle(&data_header[0],&data_header[eof_check],1);
                }
                else
                     perror("Unexpected Read Failure");
            }
            return NULL;
        }
        mess_id = data_header[0]*256 + data_header[1];
        mess_len = data_header[2]*256 + data_header[3];
/*
 * Now see what record type we appear to have found
 */
        if ((h = lookup(dfsdrive_base.idt, mess_id)) == (HIPT *) NULL)
        {
            (void) fprintf(stderr,
                  "Format failure: unrecognised message ID read:%d length %d\n",
                   mess_id, mess_len);
            gen_handle(&data_header[0],&data_header[4],1);
#ifdef AIX
            (void) smart_read(fileno(fp), &buf[0],mess_len);
#else
            (void)  fread(&buf[0],sizeof(char),mess_len,fp);
#endif
            gen_handle(&buf[0],&buf[mess_len],1);
            return NULL;
        }
        dmp = ((struct dfs_mess *) (h->body));
/*
 * Read the record
 */
#ifdef AIX
        if ((eof_check = smart_read(fileno(fp), &buf[0],mess_len)) != mess_len)
#else
        if ((eof_check = fread(buf,sizeof(char),mess_len,fp)) != mess_len)
#endif
        {
            (void) fputs( "Format failure: record read failed\n", stderr);
            if (eof_check)
            {
                (void)printf( "Format failure for type: %d length %d\n", 
                        mess_id, mess_len);
                gen_handle(&buf[0],&buf[eof_check],1);
                fflush(stdout);
            }
            else
                (void) fputs( "EOF on communications channel\n", stderr);
            return NULL;
        }
#ifdef NEED_ASCII
/*
 * Note that this is incompatible with the DEBUG levels set below
 */
        x = b + sprintf(b,"%s|",dmp->mess_name);
        e2rec_conv(0, buf, x, dmp->mess_io, '|');
#endif
        if (dfsdrive_base.debug_level > 2)
        {
            memcpy(b,&data_header[0], 4);
            memcpy(b+4,&buf[0],mess_len + 4);
        }
    }
    if (dfsdrive_base.debug_level > 2)
    {
        fprintf(stderr, "Read Message Type: %d Message Length: %d\n",
                     mess_id, mess_len);
        (void) dfsoutrec(stderr, b, IN);
        fflush(stderr);
    }
    return dmp;
}
/***************************************************************
 * dfsoutrec() - write out a record
 *
 * The input data is always in binary format. If IN, it is written out
 * out in ASCII; if OUT, it is written out in binary.
 */
struct dfs_mess * dfsoutrec(fp, b, in_out)
FILE * fp;
unsigned char * b;
enum direction_id in_out;
{
static unsigned char buf[1048];
char * x;
int buf_len;
int i;
int mess_len;
struct dfs_mess * dmp;
HIPT *h;
int mess_id;

    if (fp == (FILE *) NULL 
      || b == (unsigned char *) NULL)
    {
         (void) fputs(
               "Logic Error: dfsoutrec() called with NULL parameter(s)\n",
                  stderr );
         return NULL;
    }
    mess_id = b[0]*256 + b[1];
    mess_len = b[2]*256 + b[3];
    if ((h = lookup(dfsdrive_base.idt, mess_id)) == (HIPT *) NULL)
    {
        (void) fprintf(stderr,
          "Format failure: submitted unknown message ID:%d length:%d\n", 
               mess_id, mess_len);
        gen_handle(b,b+4+mess_len,1);
        return (struct dfs_mess *) NULL;
    }
    dmp = ((struct dfs_mess *) (h->body));
    if (in_out == OUT)
    {
        buf_len = mess_len + 4;
        buf_len = fwrite(b,sizeof(char),buf_len,fp);
        if (dfsdrive_base.debug_level > 1)
             (void) fprintf(stderr,
                   "Message %d Length %d Sent with return code: %d\n",mess_id,
                          mess_len + 4, buf_len);
        if (dfsdrive_base.debug_level > 2)
            (void) dfsoutrec(stderr, b, IN);
    }
    else
    {
/*
 * Convert the record
 */
        i = e2rec_conv(0, b+4, &buf[0], dmp->mess_io, '|');
        fputs(dmp->mess_name, fp);
        fputc('|', fp);
        if (i)
        {
            if (fp == stdout)
                asc_handle(&buf[0], &buf[i], 1);
            else
                fwrite(&buf[0],sizeof(char), i,fp);
        }
        fputc('\n', fp);
        buf_len = 1;
    }
    if (dfsdrive_base.debug_level > 2)
        (void) fprintf(stderr,"dfsoutrec() File Descriptor: %d\n",
                       fileno(fp));
    if (buf_len <= 0)
        return (struct dfs_mess *) NULL;
    else
        return dmp;
}
