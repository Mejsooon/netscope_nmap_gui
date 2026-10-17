import uvicorn

HOST = "127.0.0.1"
PORT = 8000


def main() -> None:
    uvicorn.run("app.main:app", host=HOST, port=PORT)


if __name__ == "__main__":
    main()
