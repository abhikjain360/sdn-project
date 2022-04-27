# Flow-Based IDS on P4 Switch

## Dependencies

The code has only been tested to run on linux.

Following needs to be installed inorder to run the model:

- [`p4c compiler`](https://github.com/p4lang/p4c)
- [`behaviour-model (bmv2)`](https://github.com/p4lang/behavioral-model)
- [`runtime_CLI.py`] script, as well as python enviroment to run it. The script can be found [here](https://github.com/p4lang/behavioral-model/blob/main/tools/runtime_CLI.py) in `behavioral-model`'s repository.
- `iproute2` tools to create virtual dummy interfaces to bind the p4 switch to.
- `dummy` linux model to create virtual interfaces.
- [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

The above dependencies will get the model running on a bmv2 instance. If you wish to inspect packets, you will need a network device capturing tool like `wireshark`.

To run the scripts provided inside `genpacket` directory, you'll need `rust` compiler and `cargo` toolchain installed.

## How to Run

1. Train the random forest model, export the model into XGBoost's JSON format, using the following features in order:
	1. PSH Flag Count
	2. Flow Duration
	3. SYN Flag Count
	4. ACK Flag Count
	5. Total Packets
	6. Total Length of Forwarded Packets
	7. Initial Window Bytes Forward
	8. Active Minimum
	9. Flow Inter-Arrival-Time (IAT) Minimum

   You can also use the pre-trained model output, provided in the `model_output.json`, or train your model using our jupyter notebook at `Untitled.py`.
2.

## Acknowledgements

- [SwitchTree](https://github.com/ksingh25/SwitchTree)
- [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter)
