#include "linkedList.h"
#include <stdlib.h>

int main() {
    LinkedList list;
    initialize(&list);

    Node* node1 = (Node*)malloc(sizeof(Node));
    Node* node2 = (Node*)malloc(sizeof(Node));
    Node* node3 = (Node*)malloc(sizeof(Node));

    push_back(&list, node1);
    push_back(&list, node2);
    push_back(&list, node3);

    printList(&list);

    clear(&list);

    printList(&list);

    return 0;
}