# Flow-Based IDS on P4 Switch

## Dependencies

The code has only been tested to run on Linux.

Following needs to be installed in order to run the model:

- [`behaviour-model (bmv2)`](https://github.com/p4lang/behavioral-model). Refer to repository's README for installation instructions.
- [`p4c compiler`](https://github.com/p4lang/p4c). Refer to repository's README for installation instructions.
- `runtime_CLI.py` script, as well as python environment to run it. The script can be found [here](https://github.com/p4lang/behavioral-model/blob/main/tools/runtime_CLI.py) in `behavioral-model`'s repository.
- `iproute2` tools to create virtual dummy interfaces to bind the p4 switch to.
- `dummy` Linux model to create virtual interfaces.
- [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

The above dependencies will get the model running on a bmv2 instance. If you wish to inspect packets, you will need a network device capturing tool like `wireshark`.

To run the scripts provided inside `genpacket` directory, you'll need `rust` compiler and `cargo` toolchain installed.

We provide a `requirements.txt` to install all the python dependencies required to run all scripts using `pip`. Run the following:
```sh
pip install -r requirements.txt

```

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

You can also use the pre-trained model output, provided in the `model_output.json`, or train your model using our script `train_model.py`. To train the model using the script, you must have installed `xgboost==1.5.2`, `pandas==1.4.1` and `scikit-learn==1.0.2`. Run:
```sh
pip install xgboost==1.5.2 pandas==1.4.1 scikit-learn==1.0.2
python train_model.py
```

2. Generate the match-and-action rules by using the `pyJsonParser.py`. It will output the required tables to `commands.txt`, so need to redirect the output while running the script.
```sh
python pyJsonParser.py
```

3. Modify the `swtitchtree.p4` file according to your random forest's structure. Currently it is set to handle 5 trees, each with depth of 5, and threshold for binary classification to 0.5. If the csv files you have used to train model use different timeout durations for active flow timeout duration and flow timeout duration, then also change these parameters in p4.

4. Modify the `commands.txt` to clear all the tables, and then add your required forwarding rules based on malware detection to it as well on the table `p4_exact`. See the section 'Table Naming and Match Rules' for further details.

5. Compile the `swtitchtree.p4` program using p4c.
```sh
p4c --target bmv2 --arch v1model swtichtree.p4
```

6. Generate the dummy interfaces which the virtual p4 switch will bind to/listen on. This allows us to send packets to switch by sending packets to these dummy interfaces.

7. Create dummy network interfaces to which p4 switch can bind to. We provide a `create_virtual_interfaces.sh` script to do that but requires `iproute2` as a dependency. It creates dummy interfaces with names `eth00`, `eth01`, and so on. The only argument it takes in 1 less than total number of interfaces you wish to create. So, in order to create 3 interfaces names `eth00`, `eth01` and `eth02`
```sh
./create_virtual_interfaces.sh 2
```

To manually create a dummy interface, run:
```sh
sudo modprobe dummy
sudo ip link add <interface-name> type dummy
sudo ip link set dev <interface-name> mtu 65536
sudo ip link set <interface-name> up
```

8. Run the output of compilation using [`simple_switch`] (which is obtained when installing bmv2) and bind it's port to dummy interfaces that we created in previous step.
```sh
sudo simple_switch -i 0@eth00 -i 1@eth01 -i 2@eth02 swtichtree.json
```

9. Pass on the commands from `commands.txt` to the running instance of switch using `runtime_CLI.py` script. This requires `p4runtime==1.3.0` and `thrift==0.15.0`.
```sh
runtime_CLI.py < commands.txt
```

## Table Naming and Match Rules

Trees and levels of trees start at index 0. Each match rule corresponds to each node in that particular decision tree. Each table corresponds to a particular level in that tree. So, for the first tree at first (root) level, the table you should add records to is `tree0_level0`. The table naming convention is `table<table_index>_level<level_index>`. By default, we use 5 trees with upto 5 levels in each tree. If this is not the case with your model, the `swtichtree.p4` file needs to be changed accordingly to add more tables.

## Acknowledgements

- [SwitchTree](https://github.com/ksingh25/SwitchTree)
- [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter)
- [p4lang](https://p4.org/)
