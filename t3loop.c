/*****************************************************************************
 * t3loop.c - Logic to support looping of scripts drawn from WebLogic t3
 *            network captures.
 *
 * The difficulty with making t3 scripts loop is due to the manner in which
 * the repeated send of objects is handled. What appears to happen is:
 * -  A pool of objects is managed
 * -  The pool is ordered
 * -  Each time an object is sent, it changes places with the object
 *    above it in the pecking order
 * -  When the pool is full, the bottom-most object gets over-written
 * -  The first time an object is sent, its reference, and the object itself,
 *    are transmitted
 * -  For subsequent sends, just the reference is sent
 * As a consequence, the object reference is volatile.
 *
 * The above may be an over-simplification. An obvious unanswered question is,
 * what happens if an object that has already been sent is modified after it
 * has been first sent. As described above, its reference will be sent, but not
 * the revised value. There does not appear to be a mechanism for simply
 * invalidating pooled objects. It is possible that some as yet unobserved
 * property of the communication ensures that things that have been sent never
 * change, or changed objects become new objects for transmission purposes.
 *
 * When we loop, we re-cycle a message with particular pool location values.
 * Even if an object is still in the pool, it is rather unlikely that it will
 * be in exactly the same location as it was when the message was first sent,
 * and if has been aged out of the pool the message by itself provides no
 * means by which it can be re-constructed in its entirety.
 *
 * In order to be able to loop, we would need to remember:
 * - All transmitted objects
 * - Keys to them based on the original capture reference and message sequence  
 * - An accurate implementation of the WebLogic bubbling pool.
 *
 */ 
