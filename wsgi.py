from eval_app.dotenv import load_local_env

load_local_env()

from eval_app import create_app  # noqa: E402

app = create_app()
