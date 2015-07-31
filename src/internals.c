#include "internals.h"

/*
 * Messages
 *  __  __
 * |  \/  |
 * | \  / | ___  ___ ___  __ _  __ _  ___  ___
 * | |\/| |/ _ \/ __/ __|/ _` |/ _` |/ _ \/ __|
 * | |  | |  __/\__ \__ \ (_| | (_| |  __/\__ \
 * |_|  |_|\___||___/___/\__,_|\__, |\___||___/
 *                              __/ |
 *                             |___/
 */

#define QUEUESIZE 128

typedef struct {
    bstring q[QUEUESIZE];
    int first;
    int last;
    int count;
} queue;

static void init_queue(queue *q)
{
    q->first = 0;
    q->last = QUEUESIZE - 1;
    q->count = 0;
}

static queue message_queue;

static void enqueue(queue *q, bstring *x)
{
    check(q->count < QUEUESIZE, "queue has no more room: %s\n", bdata(*x));

    q->last = (q->last + 1) % QUEUESIZE;
    q->q[q->last] = *x;
    q->count = q->count + 1;
    return;

    error:
    bdestroy(*x);
}

static bstring *dequeue(queue *q)
{
    bstring *x = NULL;

    check(q->count > 0, "Attempted delete from empty queue");
    x = &q->q[q->first];
    q->first = (q->first + 1) % QUEUESIZE;
    q->count = q->count - 1;

    error:
    return x;
}

static int is_queue_empty(queue *q)
{
    return q->count < 1;
}

void init_messages() {
    init_queue(&message_queue);
}

void add_message(bstring *message) {
    enqueue(&message_queue, message);
}

bstring *pop_message() {
    return dequeue(&message_queue);
}

int messages_empty() {
    return is_queue_empty(&message_queue);
}
