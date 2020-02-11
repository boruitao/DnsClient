package dns;

import java.util.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;

public class DnsClient {

	private static final int DEFAULT_TIMEOUT = 5000;
	private static final int DEFAULT_MAX_RETRIES = 3;
	private static final String DEFAULT_PORT = "53";
	private static final String DEFAULT_SERVER_TYPE = "A";
	private static final int MAX_DNS_PACKET_SIZE = 512;

	private int timeout;
	private int maxRetries;
	private String port;
	private String serverType;
	private String server;
	private byte[] serverAddress = new byte[4];
	private String name;

	public DnsClient() {
		timeout = DEFAULT_TIMEOUT;
		maxRetries = DEFAULT_MAX_RETRIES;
		port = DEFAULT_PORT;
		serverType = DEFAULT_SERVER_TYPE;
	}

	public static void main(String[] args) {
		DnsClient dnsClient = new DnsClient();
		dnsClient.getCmdArguments(args);
		dnsClient.createDnsRequest(1);
	}

	public void getCmdArguments(String[] args) {
		try {
			parseCmdArguments(args);
			if (server == null || name == null) {
				throw new IllegalArgumentException(
						"ERROR\tIncorrect input syntax: server ID or domain name is missing.");
			}
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"ERROR\tIncorrect input syntax: Please use the following Syntax: [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name.");
		}
	}

	private void parseCmdArguments(String[] args) {
		for (int i = 0; i < args.length; i++) {
			switch (args[i]) {
			case "-t":
				timeout = Integer.parseInt(args[i + 1]) * 1000;
				break;
			case "-r":
				maxRetries = Integer.parseInt(args[i + 1]);
				break;
			case "-p":
				port = args[i + 1];
				break;
			case "-mx":
				serverType = "MX";
				break;
			case "-ns":
				serverType = "NS";
				break;
			default:
				if (args[i].contains("@")) {
					server = args[i].substring(1);
					name = args[i + 1];
				}
				break;
			}
		}
	}

	public void createDnsRequest(int retryNum) {
		System.out.println("DnsClient sending request for " + name);
		System.out.println("Server: " + server);
		System.out.println("Request type: " + serverType);
		tryDnsRequest(retryNum);
	}

	public void tryDnsRequest(int retryNum) {
		if (retryNum <= maxRetries) {
			InetAddress serverIpAddress = getServerIPAddress();
			try {
				DatagramSocket socket = new DatagramSocket();
				socket.setSoTimeout(timeout);

				Random id = new Random(Short.MAX_VALUE + 1);
				DnsHeader packetHeader = new DnsHeader((short) id.nextInt(), (byte) 0, (byte) 0, (byte) 0, (byte) 0,
						(byte) 1, (byte) 0, (byte) 0, (byte) 0, (short) 1, (short) 0, (short) 0, (short) 0);
				int headerSize = packetHeader.getHeader().length;

				DnsQuestion question = new DnsQuestion(name, serverType);
				int questionSize = question.getQuestion().length;

				ByteBuffer requestData = ByteBuffer.allocate(headerSize + questionSize);
				requestData.put(packetHeader.getHeader());
				requestData.put(question.getQuestion());
				byte[] responseData = new byte[MAX_DNS_PACKET_SIZE];

				DatagramPacket sentPacket = new DatagramPacket(requestData.array(), requestData.array().length,
						serverIpAddress, Integer.parseInt(port));
				DatagramPacket receivedPacket = new DatagramPacket(responseData, responseData.length);

				long startTime = System.currentTimeMillis();
				socket.send(sentPacket);
				socket.receive(receivedPacket);
				long endTime = System.currentTimeMillis();
				socket.close();

				double deltaTime = (endTime - startTime) / 1000.;
				System.out
						.println("Response received after " + deltaTime + " seconds (" + (retryNum-1) + " retries)");

				byte[] receivedHeader = Arrays.copyOfRange(receivedPacket.getData(), 0, headerSize);
				byte[] receivedQuestion = Arrays.copyOfRange(receivedPacket.getData(), headerSize,
						headerSize + questionSize);

				packetHeader.parseHeader(receivedHeader);
				question.parseQuestion(receivedQuestion);
				if (!question.getQTYPE().equals(serverType)) {
					throw new RuntimeException("ERROR\tResponse query is not consistent with the original request");
				}

				DnsResponse response = new DnsResponse(receivedPacket.getData(), packetHeader, question,
						headerSize + questionSize);
				response.printResponseOutput();
			} catch (SocketException e) {
				System.out.println("ERROR\tFailed to create the socket");
			} catch (SocketTimeoutException e) {
				System.out.println("ERROR\tTimeout occurred");
				System.out.println("Retrying the original request (" + (maxRetries-retryNum-1) + " retries left) ... ");
				tryDnsRequest(++retryNum);
			} catch (IOException e) {
				System.out.println("ERROR\tThe DNS packet wasn't successfully received");
			}

		} else {
			System.out.println("ERROR\tMaximum number of retries " + maxRetries + " exceeded");
			return;
		}
	}

	public InetAddress getServerIPAddress() {
		InetAddress serverIpAddress = null;
		try {
			String[] ipComponents = server.split("\\.");
			for (int i = 0; i < ipComponents.length; i++) {
				int ip = Integer.parseInt(ipComponents[i]);
				if (ip < 0 || ip > 255) {
					throw new NumberFormatException("ERROR\tThe IP value must be <= 225 and >= 0");
				}
				serverAddress[i] = (byte) ip;
			}
			serverIpAddress = InetAddress.getByAddress(serverAddress);
		} catch (UnknownHostException e) {
			System.out.println("ERROR\tThe IP address cannot be resolved in the sender");

		} catch (NullPointerException f) {
			System.out.println("ERROR\tThe IP Address is missing entries");
		}
		return serverIpAddress;
	}
}
