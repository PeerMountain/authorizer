from kombu import Exchange, Queue


writer_exchange = Exchange('writer_exchange', 'direct', durable=True)
writer_queue = Queue('writer_queue', exchange=writer_exchange, routing_key='writer')
