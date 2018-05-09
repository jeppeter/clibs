#include <stdio.h>

typedef struct __base {
    int m_1;
    char* m_2;
    char** m_3;
    struct __base* m_4;
} base_t, *pbase_t;

static char* st_base1_default[] = {
	"cc",
	"dd",
	NULL
};

static base_t st_base1[] = {
    {0,    "hello" , st_base1_default , NULL},
    {0,    NULL    , NULL             , NULL}
};

int main(int argc, char* argv[])
{
    int i, j;
    int ret = 0;
    base_t* pcurbase;
    for (i = 0;; i++) {
        if (st_base1[i].m_2 == NULL) {
            break;
        }
        pcurbase = &(st_base1[i]);
        printf("m_1 %d\n", pcurbase->m_1);
        printf("m_2 %s\n", pcurbase->m_2);
        printf("m_3 ");
        if (pcurbase->m_3 != NULL) {
            for (j = 0;; j++) {
                if (pcurbase->m_3[j] == NULL) {
                    break;
                }
                if (j > 0){
                	printf(",");
                }
                printf("%s", pcurbase->m_3[j]);
            }
            if (j > 0){
            	printf(",");
            }
            printf("NULL\n");
        } else {
            printf("NULL\n");
        }
    }
    return ret;
}