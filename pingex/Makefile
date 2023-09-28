#we ne to set capabilites to ping binary

all:
	cargo build --release
	sudo setcap cap_net_raw,cap_net_admin=eip target/release/pingex
	target/release/pingex ${ARGS}
clean:
	cargo clean
