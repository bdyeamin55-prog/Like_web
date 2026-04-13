# Gunicorn configuration — Render deployment
workers  = 1
threads  = 4
timeout  = 120
loglevel = "info"

def on_starting(server):
    """Master process শুরু হওয়ার আগে — একবারই চলে"""
    from app import start_scheduler
    start_scheduler()

def post_fork(server, worker):
    """Worker fork হওয়ার পরে — backup guarantee"""
    from app import start_scheduler
    start_scheduler()
