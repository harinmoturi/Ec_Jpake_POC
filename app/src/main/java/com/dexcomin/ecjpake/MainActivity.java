package com.dexcomin.ecjpake;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import com.dexcomin.ecjpake.R;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadLocalRandom;


public class MainActivity extends AppCompatActivity {

    public static Semaphore sem = new Semaphore(0);

    public static Semaphore writeSem = new Semaphore(0);

    ArrayList<Byte> received = new ArrayList<Byte>();
    short receivedRoundSize = 0;

    enum EXCHANGE {
        SERVER_HELLO,
        WRITE_ROUND_ONE,
        WRITE_ROUND_TWO,

        WRITE_ROUND_ONE_RESPONSE,
        WRITE_ROUND_TWO_RESPONSE,

        RECEIVE_ROUND_ONE,
        RECEIVE_ROUND_TWO,

        RECEIVE_ROUND_ONE_RESPONSE,
        READ_FOR_AUTH

    }

    EXCHANGE currentSyate = EXCHANGE.SERVER_HELLO;


    static <T> List<List<T>> chopped(List<T> list, final int L) {
        List<List<T>> parts = new ArrayList<List<T>>();
        final int N = list.size();
        for (int i = 0; i < N; i += L) {
            parts.add(new ArrayList<T>(
                    list.subList(i, Math.min(N, i + L)))
            );
        }
        return parts;
    }


    private BluetoothAdapter mBTAdapter;
    private BluetoothLeScanner mScanner;

    private BluetoothGattCharacteristic authChar;


    // #defines for identifying shared types between calling functions
    private final static int REQUEST_ENABLE_BT = 1; // used to identify adding bluetooth names
    private final static int MESSAGE_READ = 2; // used in bluetooth handler to identify message update
    private final static int CONNECTING_STATUS = 3; // used in bluetooth handler to identify message status


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mBTAdapter = BluetoothAdapter.getDefaultAdapter(); // get a handle on the bluetooth radio


        // Ask for location permission if not already allowed
        if (ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_COARSE_LOCATION") != PackageManager.PERMISSION_GRANTED)
            ActivityCompat.requestPermissions(this, new String[]{"android.permission.ACCESS_COARSE_LOCATION"}, 1);

        mBTAdapter = BluetoothAdapter.getDefaultAdapter(); // get a handle on the bluetooth radio

        Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
        startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT);

        mScanner = mBTAdapter.getBluetoothLeScanner();


        mScanner.startScan(new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {

                BluetoothDevice deviceToConnect = result.getDevice();

                if (deviceToConnect.getName() != null && deviceToConnect.getName().contains("Dexcom")) {

                    mScanner.stopScan(this);

                    deviceToConnect.connectGatt(getBaseContext(), false, new BluetoothGattCallback() {

                        @Override
                        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {

                            try {
                                Thread.sleep(2000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }

                            super.onConnectionStateChange(gatt, status, newState);


                            if (newState == BluetoothProfile.STATE_CONNECTED) {
                                gatt.discoverServices();
                            }
                        }

                        @Override
                        public void onServicesDiscovered(final BluetoothGatt gatt, int status) {
                            super.onServicesDiscovered(gatt, status);

                            // Let's process the services in a new threads
                            Runnable task = new Runnable() {
                                public void run() {
                                    for (BluetoothGattService service : gatt.getServices()) {

                                        System.out.println(service.getUuid().toString());

                                        if (service.getUuid().toString().equals("f8083532-849e-531c-c594-30f1f86a4ea5")) {

                                            for (BluetoothGattCharacteristic charcacteristic : service.getCharacteristics()) {

                                                /* Subscribe to Auth Characteristic */

                                                if (charcacteristic.getUuid().toString().equals("f8083535-849e-531c-c594-30f1f86a4ea5")) {

                                                    authChar = charcacteristic;

                                                    for (final BluetoothGattDescriptor desc : charcacteristic.getDescriptors()) {


                                                        desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);

                                                        if (gatt.writeDescriptor(desc)) {
                                                            try {
                                                                sem.acquire();
                                                            } catch (InterruptedException e) {
                                                                e.printStackTrace();
                                                            }
                                                            System.out.println("We can write!!");
                                                        }


                                                    }

                                                    gatt.setCharacteristicNotification(charcacteristic, true);

                                                }

                                                /* Subscribe to Exchange Characteristic */
                                                if (charcacteristic.getUuid().toString().equals("f8083536-849e-531c-c594-30f1f86a4ea5")) {

                                                    for (BluetoothGattDescriptor desc : charcacteristic.getDescriptors()) {

                                                        desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                                                        if (gatt.writeDescriptor(desc)) {
                                                            try {
                                                                sem.acquire();
                                                            } catch (InterruptedException e) {
                                                                e.printStackTrace();
                                                            }
                                                            if (gatt.setCharacteristicNotification(charcacteristic, true)) {

                                                                // Now we can finally run the pake protocol
                                                                doECJPAKE(gatt);


                                                            }
                                                        } else {
                                                            System.out.println("We could not write the char!");

                                                        }
                                                        desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                                                        if (gatt.writeDescriptor(desc)) {
                                                            System.out.println("We can write!!");
                                                        }

                                                    }

                                                }
                                            }

                                        }
                                    }
                                }
                            };

                            new Thread(task).start();

                        }

                        @Override
                        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {

                            super.onCharacteristicWrite(gatt, characteristic, status);

                            System.out.println(authChar.getWriteType());
                            if (characteristic == authChar)
                                writeSem.release();

                        }

                        /**
                         * We need to latch into when the descriptor writes so we
                         * @param gatt
                         * @param descriptor
                         * @param status
                         */
                        @Override
                        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {

                            System.out.println("We got a response");

                            sem.release();

                            super.onDescriptorWrite(gatt, descriptor, status);

                        }

                        @Override
                        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {

                            super.onCharacteristicChanged(gatt, characteristic);


                            System.out.println(bytesToHex(characteristic.getValue()));

                            switch (currentSyate) {
                                case READ_FOR_AUTH:
                                    received = new ArrayList<>();
                                    for (int i = 1; i < characteristic.getValue().length; i++) {
                                        received.add(characteristic.getValue()[i]);
                                    }
                                    sem.release();
                                    break;
                                case SERVER_HELLO:
                                    if (characteristic.getValue()[0] == 0x0B) {
                                        for (int i = 1; i < characteristic.getValue().length; i++) {
                                            received.add(characteristic.getValue()[i]);
                                        }
                                    }
                                    sem.release();

                                    break;

                                case WRITE_ROUND_ONE_RESPONSE:

                                    received = new ArrayList<Byte>();
                                    for (int i = 1; i < characteristic.getValue().length; i++) {
                                        received.add(characteristic.getValue()[i]);
                                    }

                                    currentSyate = EXCHANGE.RECEIVE_ROUND_ONE;

                                    sem.release();

                                    break;

                                case WRITE_ROUND_TWO_RESPONSE:

                                    received = new ArrayList<Byte>();
                                    for (int i = 1; i < characteristic.getValue().length; i++) {
                                        received.add(characteristic.getValue()[i]);
                                    }

                                    currentSyate = EXCHANGE.RECEIVE_ROUND_TWO;

                                    sem.release();

                                    break;

                                case RECEIVE_ROUND_ONE:
                                case RECEIVE_ROUND_TWO:


                                    if (characteristic.getValue()[0] == 0x00) {

                                        // Now we are going to parse the payload size
                                        byte[] size = new byte[]{characteristic.getValue()[1], characteristic.getValue()[2]};
                                        ByteBuffer wrapped = ByteBuffer.wrap(size); // big-endian by default
                                        receivedRoundSize = wrapped.getShort();

                                        // Case to a short
                                        receivedRoundSize = (short) (receivedRoundSize + 2);

                                        // Now we are going to set its initial capacity
                                        received = new ArrayList<Byte>(receivedRoundSize);

                                        System.out.println("We got the round size!!");
                                    }

                                    for (int i = 1; i < characteristic.getValue().length; i++) {
                                        received.add(characteristic.getValue()[i]);
                                    }

                                    // Check to see if we got all the data
                                    if (received.size() == receivedRoundSize) {

                                        System.out.println("We got the round size!!");

                                        sem.release();


                                    }

                                    break;

                                default:
                                    break;
                            }


                        }
                    });
                }
            }
        });


    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }

        return result;
    }

    public void doECJPAKE(BluetoothGatt gatt) {


        System.loadLibrary("ecjpake");

        try {


            this.currentSyate = EXCHANGE.SERVER_HELLO;

            Instant start = Instant.now();
//            this.status.setText("Initiating...");

            // Let's setup
            ecjpake.init();

            // Let's get our hello data back :)
            byte[] helloData = ecjpake.sayHello();

            authChar.setValue(helloData);
            authChar.setWriteType(0x02);
            gatt.writeCharacteristic(authChar);

            // Let's wait until we have written since we need a response
            writeSem.acquire();

            //We will now wait for the TX to ack back that it received the first round
            sem.acquire();


            // Now we are going to set the info
            Byte[] myArray = new Byte[received.size()];
            received.toArray(myArray);
            ecjpake.setInfo(toPrimitives(myArray));

            currentSyate = EXCHANGE.RECEIVE_ROUND_ONE;

            // Now we are going to write the first round
            byte[] data = ecjpake.writeRoundOneJ();
            authChar.setWriteType(0x01);
            List<byte[]> roundOneChopped = divideArray(data, 19);
            write(gatt, roundOneChopped, (byte) 0x00);


            // Wait for the response and then wait for the receiver to send the rest
            sem.acquire();

            myArray = new Byte[received.size()];
            received.toArray(myArray);
            ecjpake.readRoundOneJ(toPrimitives(myArray));


            authChar.setValue(new byte[]{0x0C, 0x01});
            authChar.setWriteType(0x02);
            gatt.writeCharacteristic(authChar);

            // Let's wait until we have written since we need a response
            writeSem.acquire();


            currentSyate = EXCHANGE.RECEIVE_ROUND_TWO;

            byte[] roundTwo = ecjpake.writeRoundTwoJ();
            authChar.setWriteType(0x01);
            List<byte[]> roundTwoChopped = divideArray(roundTwo, 19);
            write(gatt, roundTwoChopped, (byte) 0x00);


            // Wait for the response and then wait for the receiver to send the rest
            sem.acquire();

            myArray = new Byte[received.size()];
            received.toArray(myArray);
            ecjpake.readRoundTwoJ(toPrimitives(myArray));

            byte[] key = ecjpake.getKey();

            Instant finish = Instant.now();

            long timeElapsed = Duration.between(start, finish).toMillis();  //in millis

            System.out.println("It took: " + timeElapsed);

            System.out.println("HERE IS THE KEY " + bytesToHex(key));

            System.out.println(bytesToHex(key));

            currentSyate = EXCHANGE.READ_FOR_AUTH;

            doAuthentication(key, gatt, start);


        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void doAuthentication(byte[] key, BluetoothGatt gatt, Instant start) throws InterruptedException {


        byte[] challengeFromDisplay = new byte[]{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

        byte[] hashValue = new byte[16];

        for (int i = 1; i < 9; i++) {
            challengeFromDisplay[i] = (byte) ThreadLocalRandom.current().nextInt(0, 127 + 1);
            hashValue[i - 1] = challengeFromDisplay[i];
            hashValue[i - 1 + 8] = challengeFromDisplay[i];
        }


        byte[] encryptedHash = AES.encrypt(hashValue, key);

        System.out.println(bytesToHex(encryptedHash));

        authChar.setWriteType(0x02);
        authChar.setValue(challengeFromDisplay);
        gatt.writeCharacteristic(authChar);

        sem.acquire();


        // Now we need to compare the hashes
        for (int i = 0; i < 8; i++) {
            if (encryptedHash[i] != received.get(i)) {
                return;
            }
        }


        byte[] txChallenge = new byte[16];

        for (int i = 8; i < 16; i++) {
            txChallenge[i - 8] = received.get(i);
            txChallenge[i + 8 - 8] = received.get(i);

        }

        byte[] txChallengeHash = AES.encrypt(txChallenge, key);

        byte[] txChallengeHashFinal = new byte[]{0x04, 0, 0, 0, 0, 0, 0, 0, 0};

        for (int i = 1; i < 9; i++) {
            txChallengeHashFinal[i] = txChallengeHash[i - 1];

        }

        authChar.setValue(txChallengeHashFinal);
        gatt.writeCharacteristic(authChar);

        sem.acquire();




    }

    private void write(BluetoothGatt gatt, List<byte[]> roundOneChopped, byte phaseHeader) throws InterruptedException {


        for (int i = 0; i < roundOneChopped.size(); i++) {


            byte[] valueToWrite = new byte[roundOneChopped.get(i).length + 1];
            valueToWrite[0] = phaseHeader;

            for (int e = 1; e < valueToWrite.length; e++) {
                valueToWrite[e] = roundOneChopped.get(i)[e - 1];
            }

            authChar.setValue(valueToWrite);
            gatt.writeCharacteristic(authChar);
            phaseHeader = (byte) (phaseHeader + 1);

            writeSem.acquire();
        }
    }


    byte[] toPrimitives(Byte[] oBytes) {

        byte[] bytes = new byte[oBytes.length];
        for (int i = 0; i < oBytes.length; i++) {
            bytes[i] = oBytes[i];

        }
        return bytes;

    }

}
