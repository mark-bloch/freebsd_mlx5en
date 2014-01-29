/*----------------------------------------------------------------*/
/* Macros                                                         */
/*----------------------------------------------------------------*/
/* These macros were based on VL */

/* --------------------------- macros to check values of functions --------------------------- */

#define MAX_BUF_SIZE 1024
#define SUCCESS 0
#define FAIL 1

#define VL_CHECK_INT_VALUE(actual_val, expected_val, cmd, log, failure_text)				\
	if ((actual_val) != (expected_val)) {								\
		char buff[MAX_BUF_SIZE];								\
		snprintf(buff, MAX_BUF_SIZE,"%s@%s +%d %s, expected_val = %d, actual_val = %d\n",       \
                             __func__, __FILE__, __LINE__, failure_text, expected_val, actual_val);	\
		uprintf("%s", buff);									\
		strncpy(log, buff, MAX_BUF_SIZE);							\
		cmd;											\
	}

#define VL_CHECK_LONG_LONG_INT_VALUE(actual_val, expected_val, cmd, log, failure_text)          	\
        if ((actual_val) != (expected_val)) {                                                   	\
		char buff[MAX_BUF_SIZE];                                                                \
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, expected_val = %lu, actual_val = %lu\n",  \
                             __func__, __FILE__, __LINE__, failure_text, expected_val, actual_val);     \
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

#define VL_CHECK_LONG_INT_VALUE(actual_val, expected_val, cmd, log, failure_text)               	\
        if ((actual_val) != (expected_val)) {                                                   	\
		char buff[MAX_BUF_SIZE];                                                                \
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, expected_val = %lu, actual_val = %lu\n",    \
                             __func__, __FILE__, __LINE__, failure_text, expected_val, actual_val);     \
		uprintf("%s", buff);									\
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

#define VL_CHECK_UNSIGNED_INT_VALUE(actual_val, expected_val, cmd, log, failure_text)           	\
        if ((actual_val) != (expected_val)) {								\
		char buff[MAX_BUF_SIZE];                                                   		\
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, expected_val = %u, actual_val = %u\n",      \
                             __func__, __FILE__, __LINE__, failure_text, expected_val, actual_val);     \
		uprintf("%s", buff);									\
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }


/* macro to check allocation of pointers */
#define VL_CHECK_MALLOC(ptr, cmd, log)									\
	if (!(ptr)) {											\
		char buff[MAX_BUF_SIZE];								\
		snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d failed to allocate memory for %s\n",		\
			     __func__, __FILE__, __LINE__, #ptr);					\
		uprintf("%s", buff);					                               	\
                strncpy(log, buff, MAX_BUF_SIZE);					           	\
                cmd;											\
	}


/* macro to check the return code of functions */
#define VL_CHECK_RC(actual_rc, expected_rc, cmd, log, failure_text)                      		\
        if ((actual_rc) != (expected_rc)) {                                                     	\
                char buff[MAX_BUF_SIZE];                                                                \
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, expected_rc = %d, actual_rc = %d\n",        \
                             __func__, __FILE__, __LINE__, failure_text, expected_rc, actual_rc);	\
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);							\
		cmd;                                                               			\
        }

/* ------------------------------------------ GREATER ---------------------------------------- */
/* this macros check that the first value given is grater than the second */

#define VL_CHECK_GREATER(first_value, second_value, cmd, log, failure_text)                     	\
        if ((first_value) <= (second_value)) {                                                  	\
		char buff[MAX_BUF_SIZE];								\
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, first_val = %d <= second_val = %d\n",       \
                             __func__, __FILE__, __LINE__, failure_text, first_value, second_value);    \
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

#define VL_CHECK_GREATER_LONG(first_value, second_value, cmd, log, failure_text)                	\
        if ((first_value) <= (second_value)) {                                                  	\
		char buff[MAX_BUF_SIZE];                                                                \
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, first_val = %lu <= second_val = %lu\n",     \
                             __func__, __FILE__, __LINE__, failure_text, first_value, second_value);    \
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

/* ------------------------------------------- LESS ------------------------------------------ */
/* this macro checks that the first value given is less than the second */

#define VL_CHECK_LESS(first_value, second_value, cmd, log, failure_text)                        	\
        if ((first_value) < (second_value)) {                                                   	\
		char buff[MAX_BUF_SIZE];								\
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, first_val = %d < second_val = %d\n",        \
                             __func__, __FILE__, __LINE__, failure_text, first_value, second_value);    \
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

/* ------------------------------------------- EQUALS ------------------------------------------ */
/* this macro checks that both values equals */

#define VL_CHECK_EQUALS(first_value, second_value, cmd, log, failure_text)                      	\
        if ((first_value) == (second_value)) {                                                  	\
		char buff[MAX_BUF_SIZE];                                                                \
                snprintf(buff, MAX_BUF_SIZE, "%s@%s +%d %s, first_val = %d == second_val = %d\n",       \
                             __func__, __FILE__, __LINE__, failure_text, first_value, second_value);    \
		uprintf("%s", buff);                                                                    \
                strncpy(log, buff, MAX_BUF_SIZE);                                       		\
                cmd;                                                                            	\
        }

