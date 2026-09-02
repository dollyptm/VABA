"""WSGI gateway mounting frozen V1 and independently evolvable V2."""

import os

from flask import Flask, redirect
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

from .v1.app import app as v1_app
from .v2.app import app as v2_app


gateway_app = Flask(__name__)


@gateway_app.route("/")
def version_landing():
    return redirect("/v1/login")


@gateway_app.route("/v1")
def v1_landing():
    return redirect("/v1/login")


@gateway_app.route("/v2")
def v2_landing():
    return redirect("/v2/login")


application = DispatcherMiddleware(
    gateway_app,
    {
        "/v1": v1_app,
        "/v2": v2_app,
    },
)


def main() -> None:
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "5055"))
    run_simple(host, port, application, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
