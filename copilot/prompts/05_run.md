# Run & Operate

You will give **commands only** to run the service and exercise a demo.

```bash
uvicorn signet_api.main:app --port 8000
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange
```
