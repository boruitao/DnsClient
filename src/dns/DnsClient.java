package dns;

import java.util.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;

public class DnsClient {

	private static final int DEFAULT_TIMEOUT = 5000;
	private static final int DEFAULT_MAX_RETRIES = 3;
	private static final String DEFAULT_PORT = "53";
	private static final String DEFAULT_REQUEST_TYPE = "A";
	private static final int MAX_DNS_PACKET_SIZE = 512;

	private int timeout;
	private int maxRetries;
	private String port;
	private String requestType;
	private String server;
	private byte[] serverAddress = new byte[4];
	private String name;

	public DnsClient() {
		timeout = DEFAULT_TIMEOUT;
		maxRetries = DEFAULT_MAX_RETRIES;
		port = DEFAULT_PORT;
		requestType = DEFAULT_REQUEST_TYPE;
	}

	/**
	 * In the main class, first we parse the arguments from the command line, then
	 * we create our first DNS request.
	 * 
	 * @param args : the command line arguments
	 */
	public static void main(String[] args) {
		DnsClient dnsClient = new DnsClient();
		dnsClient.getCmdArguments(args);
		dnsClient.createDnsRequest(0);
	}

	/**
	 * If the command line arguments have incorrect syntax, or the server ID and
	 * domain name are missing, we throw an IllegalArgumentException
	 * 
	 * @param args : the command line arguments
	 */
	public void getCmdArguments(String[] args) {
		try {
			parseCmdArguments(args);
			if (server == null || name == null) {
				throw new IllegalArgumentException(
						"ERROR\tIncorrect input syntax: server IP address or domain name is missing.");
			}
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"ERROR\tIncorrect input syntax: Please use the following Syntax: [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name.");
		}
	}

	private void parseCmdArguments(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-t")) {
				timeout = Integer.parseInt(args[i + 1]) * 1000;
			} else if (args[i].equals("-r")) {
				maxRetries = Integer.parseInt(args[i + 1]);
			} else if (args[i].equals("-p")) {
				port = args[i + 1];
			} else if (args[i].equals("-mx")) {
				requestType = "MX";
			} else if (args[i].equals("-ns")) {
				requestType = "NS";
			} else if (args[i].contains("@")) {
				server = args[i].substring(1);
				name = args[i + 1];
			}
		}
	}

	public void createDnsRequest(int retryNum) {
		System.out.println("DnsClient sending request for " + name);
		System.out.println("Server: " + server);
		System.out.println("Request type: " + requestType);
		tryDnsRequest(retryNum);
	}

	/**
	 * The DNS request is created in the following steps. First, we create a packet
	 * with the packet header and the question which contains the server name, IP
	 * address, and the request type. Then we create a UDP socket to send the query
	 * and get a response. If the timeout occurs, we retransmit the query if we
	 * still have retries left. Afterwards, the header, question, and the answers
	 * are parsed based on the response data. Finally, the response output is
	 * printed.
	 * 
	 * Handled exception: 1. Cannot create socket: SocketException. 2. Timeout:
	 * SocketTimeoutException. 3. Response type and query type don't match:
	 * RuntimeException. 4. Fail to receive the packet: IOException
	 * 
	 * @param retryNum : the number of transmitted queries
	 */
	public void tryDnsRequest(int retryNum) {
		InetAddress serverIpAddress = getServerIPAddress();
		try {
			DatagramSocket socket = new DatagramSocket();
			socket.setSoTimeout(timeout);

			Random id = new Random(Short.MAX_VALUE + 1);
			DnsHeader packetHeader = new DnsHeader((short) id.nextInt(), (byte) 0, (byte) 0, (byte) 0, (byte) 0,
					(byte) 1, (byte) 0, (byte) 0, (byte) 0, (short) 1, (short) 0, (short) 0, (short) 0);
			int headerSize = packetHeader.getHeader().length;

			DnsQuestion question = new DnsQuestion(name, requestType);
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
			System.out.println("Response received after " + deltaTime + " seconds (" + retryNum + " retries)");

			byte[] receivedHeader = Arrays.copyOfRange(receivedPacket.getData(), 0, headerSize);
			byte[] receivedQuestion = Arrays.copyOfRange(receivedPacket.getData(), headerSize,
					headerSize + questionSize);

			packetHeader.parseHeader(receivedHeader);
			question.parseQuestion(receivedQuestion);
			if (!question.getQTYPE().equals(requestType)) {
				throw new RuntimeException("ERROR\tResponse type is not consistent with the original request");
			}

			DnsResponse response = new DnsResponse(receivedPacket.getData(), packetHeader, headerSize + questionSize);
			response.printResponseOutput();
		} catch (SocketException e) {
			System.out.println("ERROR\tFailed to create the socket");
		} catch (SocketTimeoutException e) {
			System.out.println("ERROR\tTimeout occurred");
			if (maxRetries >= ++retryNum) {
				System.out.println("Retrying the original request (" + (maxRetries - retryNum) + " retries left) ... ");
				tryDnsRequest(retryNum);
			} else {
				System.out.println("ERROR\tMaximum number of retries " + maxRetries + " exceeded");
				return;
			}
		} catch (IOException e) {
			System.out.println("ERROR\tThe DNS packet wasn't successfully received");
		}

	}

	/**
	 * InetAddress.getByAddress method is used to get the IP address of the server.
	 * If the host is not known, an UnknownHostException is thrown.
	 * 
	 */
	public InetAddress getServerIPAddress() {
		InetAddress serverIpAddress = null;
		try {
			String[] ipComponents = server.split("\\.");
			for (int i = 0; i < ipComponents.length; i++) {
				int ip = Integer.parseInt(ipComponents[i]);
				if (ip < 0 || ip > 255) {
					throw new NumberFormatException("ERROR\tEach of the IP component must be <= 255 and >= 0");
				}
				serverAddress[i] = (byte) ip;
			}
			serverIpAddress = InetAddress.getByAddress(serverAddress);
		} catch (UnknownHostException e) {
			System.out.println("ERROR\tThe IP address cannot be resolved in the sender");

		} catch (NullPointerException f) {
			System.out.println("ERROR\tThe IP address is missing entries");
		}
		return serverIpAddress;
	}
}
