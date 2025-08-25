
typedef struct node {
    struct node* next;
    struct node* prev;
} Node;

typedef struct linkedList {
    Node* head;
    Node* tail;
    int size;
} LinkedList;

extern void initialize(LinkedList* list);
extern void clear(LinkedList*);
extern int getSize(LinkedList*);
extern int isEmpty(LinkedList*);
extern void pop_back(LinkedList*);
extern void pop_front(LinkedList*);
extern void push_back(LinkedList*, Node* node);
extern void push_front(LinkedList*, Node* node);
extern Node* peek_back(LinkedList*);
extern Node* peek_front(LinkedList*);

extern void printList(LinkedList* list);