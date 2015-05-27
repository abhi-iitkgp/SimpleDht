package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider
{
    int current_port;
    String node_id;
    int predecessor_port;
    String predecessor_id;
    int sucessor_port;
    String sucessor_id;
    int avd_to_request_join = 11108;
    Map<String, String> received_data = Collections.synchronizedMap(new HashMap<String,String>());
    Map<String, String> all_data_in_ring = Collections.synchronizedMap(new HashMap<String, String>());
    boolean requested_data_available = false;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs)
    {
        if(selection.equals("\"*\""))
        {
            Message msg = new Message();
            msg.port_sender = current_port;
            msg.key = selection;

            try
            {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                Message msg_to_send = new Message();
                msg_to_send.message_id = MessageType.DELETE_DATA;
                msg_to_send.key = selection;
                Log.v("DELETE", "Deleting all data from current avd");
            }
            catch (Exception e)
            {

            }
        }
        else if(selection.equals("\"@\""))
        {
            // delete all files from current AVD
            File files_dir = getContext().getFilesDir();
            File [] all_data_files = files_dir.listFiles();

            for(File file : all_data_files)
            {
                getContext().deleteFile(file.getName());
            }

            Log.v("DELETE", "Deleting all data from current avd");
        }
        else
        {
            String key_hash = null;

            try
            {
                key_hash = genHash(selection);
            }
            catch (Exception e)
            {

            }
            if(predecessor_port == current_port)
            {
                Log.v("DELETE_KEY", selection);
                // delete value from storage in current avd
                getContext().deleteFile(selection);
            }
            else
            {
                if((isBetween(predecessor_id, node_id, key_hash)))
                {
                    // delete value from storage in current avd
                    Log.v("DELETE_KEY", selection);
                    getContext().deleteFile(selection);
                }
                else
                {
                    // ask other avd's to delete this key
                    try
                    {
                        Log.v("FORWARD_DELETE_KEY", selection);
                        Socket socket = new Socket();
                        socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                        Message msg_to_send = new Message();
                        msg_to_send.message_id = MessageType.DELETE_DATA;
                        msg_to_send.key = selection;

                        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                        oos.writeObject(msg_to_send);
                        socket.close();
                    }
                    catch (Exception e)
                    {

                    }
                }
            }
        }

        return 0;
    }

    @Override
    public String getType(Uri uri)
    {
        // TODO Auto-generated method stub

        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values)
    {
        // TODO Auto-generated method stub
        String key = (String)values.get("key");
        String value = (String)values.get("value");
        String key_hash = null;
        Log.v("INSERT_REQUEST_FROM_CLIENT", key + " " + value);
        Log.v("DEBUG", (predecessor_port/2) + " " + (sucessor_port/2));
        Log.v("DEBUG_succ_pred", predecessor_id + " " + node_id);

        try
        {
            key_hash = genHash(key);
        }
        catch (Exception e)
        {

        }

        if(predecessor_port == current_port || isBetween(predecessor_id, node_id, key_hash))
        {
            // insert in the storage of current avd
            Log.v("INSERT", key + " " + value);
            Log.v("TRUE_INSERT_" + key_hash, predecessor_id + " " + node_id);
            try
            {
                FileOutputStream fos = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                fos.write(value.getBytes());
                fos.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        else
        {
            // ask other avd's to add this key
            try
            {
                Log.v("INSERT_REQUEST_FORWARDED", key + " " + value);
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                Message msg_to_send = new Message();
                msg_to_send.message_id = MessageType.ADD_DATA;
                msg_to_send.key = key;
                msg_to_send.value = value;
                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                oos.writeObject(msg_to_send);
                socket.close();
            }
            catch (Exception e)
            {

            }
        }

        return null;
    }

    @Override
    public boolean onCreate()
    {
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        current_port = 2*Integer.parseInt(tel.getLine1Number().substring(tel.getLine1Number().length() - 4));
        predecessor_port = sucessor_port = current_port;
        Log.v("MY_PORT", "" + current_port);

        try
        {
            node_id = genHash((current_port/2) + "");

            new Thread(
                    new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            try
                            {
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), avd_to_request_join));
                                Message msg_to_send = new Message();
                                msg_to_send.port_sender = current_port;
                                msg_to_send.message_id = MessageType.NODE_JOIN_REQUEST;

                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(msg_to_send);
                                socket.close();
                                Log.v("SENT_JOIN_REQUEST", "sent join request to " + avd_to_request_join);
                            }
                            catch (Exception e)
                            {
                                Log.v("NODE_JOIN_REQUEST_SENT_FAILED", avd_to_request_join + "");
                            }
                        }
                    }).start();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        try
        {
            ServerTask server_task = new ServerTask(current_port, 10000);
            server_task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }
        catch (Exception e)
        {
            Log.v("SERVER_FAILED_START", e.toString());
        }

        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)
    {
        MatrixCursor matrix_cursor = new MatrixCursor(new String[] {"key", "value"});
        Log.v("got_query", selection);

        if(selection.equals("\"@\""))
        {
            Log.v("got_query", "@");
            // return key and value pairs in current avd
            File data_files_dir = getContext().getFilesDir();
            File [] all_files = data_files_dir.listFiles();

            for(File file : all_files)
            {
                String filename = file.getName();
                try
                {
                    FileInputStream fis = getContext().openFileInput(filename);
                    BufferedReader br = new BufferedReader(new InputStreamReader(fis));
                    String value = br.readLine();
                    fis.close();
                    br.close();
                    matrix_cursor.addRow(new String[] {filename, value});
                }
                catch (Exception e)
                {

                }
            }
        }
        else if(selection.equals("\"*\""))
        {
            Log.v("got_query_star", "got_query");
            Log.v("forwarding_request_to", sucessor_port + "");

            // return all key and value pairs
            try
            {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                Message msg_to_send = new Message();
                msg_to_send.message_id = MessageType.FIND;
                msg_to_send.key = selection;
                msg_to_send.port_sender = current_port;

                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                oos.writeObject(msg_to_send);
                socket.close();
            }
            catch (Exception e)
            {
                Log.e("exception_sending_data","star_query");
            }

            while(!requested_data_available)
            {
                try
                {
                    Thread.sleep(10);
                }
                catch (Exception e)
                {

                }
            }

            requested_data_available = false;
            Log.v("data_received_star_query", "data_received");
            Iterator<String> key_set = all_data_in_ring.keySet().iterator();

            while(key_set.hasNext())
            {
                String key_found = key_set.next();
                String value_found = all_data_in_ring.get(key_found);
                matrix_cursor.addRow(new String[] {key_found, value_found});
                Log.v("key", key_found + "  " + value_found);
            }
            // return data from all_data_in_ring
        }
       else
        {
            String key_hash = null;

            try
            {
                key_hash = genHash(selection);
            }
            catch (Exception e)
            {

            }

            if(predecessor_port == current_port || (isBetween(predecessor_id, node_id, key_hash)))
            {
                // get data from current AVD
                try
                {
                    FileInputStream fis = getContext().openFileInput(selection);
                    BufferedReader br = new BufferedReader(new InputStreamReader(fis));
                    String value = br.readLine();
                    matrix_cursor.addRow(new String [] {selection, value});
                }
                catch (Exception e)
                {

                }
            }
            else
            {
                // Query to other avd's
                try
                {
                    Log.v("QUERY_FORWARDED " + selection, sucessor_port + "");
                    Socket socket = new Socket();
                    socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                    Message msg_to_send = new Message();
                    msg_to_send.port_sender = current_port;
                    msg_to_send.message_id = MessageType.FIND;
                    msg_to_send.key = selection;

                    ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                    oos.writeObject(msg_to_send);
                    socket.close();

                    while(!received_data.containsKey(selection))
                    {
                        Thread.sleep(100);
                        Log.v("LOOPING_FOR_KEY", "IN LOOP");
                    }

                    matrix_cursor.addRow(new String [] {selection, received_data.get(selection)});
                    received_data.remove(selection);
                }
                catch (Exception e)
                {

                }
            }
        }

        return matrix_cursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs)
    {
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException
    {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();

        for (byte b : sha1Hash)
        {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    protected boolean isBetween(String predecessor_id, String current_id, String key)
    {
        boolean is_between = false;

        if((key.compareTo(predecessor_id) >= 0) && (key.compareTo(current_id) < 0) && (current_id.compareTo(predecessor_id) > 0))
        {
            is_between = true;
        }
        else if((key.compareTo(predecessor_id) >= 0) && (key.compareTo(current_id) > 0) && (current_id.compareTo(predecessor_id) < 0))
        {
            is_between = true;
        }
        else if((key.compareTo(predecessor_id) <= 0) && (key.compareTo(current_id) < 0) && (current_id.compareTo(predecessor_id) < 0))
        {
            is_between = true;
        }

        return is_between;
    }


    public class ServerTask extends AsyncTask<Void, String, Void>
    {
        int current_port;
        int server_port;
        public ServerTask(int current_port, int server_port)
        {
            this.current_port = current_port;this.server_port = server_port;
        }

        @Override
        protected Void doInBackground(Void... params)
        {
            try
            {
                Log.v("creating_server_socket", "creating_server_socket");
                ServerSocket server_socket = new ServerSocket(server_port);

                while(true)
                {
                    Socket client_socket = server_socket.accept();
                    Log.v("server_socket_accepted", "server_socket_accepted");
                    ObjectInputStream oin = new ObjectInputStream(client_socket.getInputStream());
                    Message received_obj = (Message)oin.readObject();

                    Log.v("message_received_type", received_obj.message_id + "");
                    if(received_obj.message_id == MessageType.FOUND_DATA)
                    {
                        Log.v("FOUND_DATA", received_obj.key + " value is " + received_obj.value);
                        received_data.put(received_obj.key, received_obj.value);
                    }

                    if(received_obj.message_id == MessageType.ADD_DATA)
                    {
                        String key = received_obj.key;
                        String key_hash = genHash(key);
                        Log.v("ADD_REQUEST_FROM_AVD", received_obj.key + "");

                        if(isBetween(predecessor_id, node_id, key_hash))
                        {
                            // insert key and value in the current avd
                            publishProgress("INSERT", key, received_obj.value);
                            Log.v("TRUE_INSERT_FROM_SERVER_" + key_hash, predecessor_id + " " + node_id);
                        }
                        else
                        {
                            // send data to next avd
                            Socket socket = new Socket();
                            socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                            oos.writeObject(received_obj);
                            socket.close();
                        }
                    }
                    else if(received_obj.message_id == MessageType.FIND)
                    {
                        String key = received_obj.key;
                        String key_hash = genHash(key);

                        if(key.equals("\"*\""))
                        {
                            File data_files_dir = getContext().getFilesDir();
                            File [] all_files = data_files_dir.listFiles();

                            for(File file : all_files)
                            {
                                String filename = file.getName();
                                FileInputStream fis = getContext().openFileInput(filename);
                                BufferedReader br = new BufferedReader(new InputStreamReader(fis));
                                String value = br.readLine();
                                fis.close();
                                br.close();
                                received_obj.key_value_data.put(filename, value);
                            }

                            if(received_obj.port_sender == current_port)
                            {
                                all_data_in_ring.putAll(received_obj.key_value_data);
                                requested_data_available = true;
                            }
                            else
                            {
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(received_obj);
                                socket.close();
                            }
                        }
                        else if(isBetween(predecessor_id, node_id, key_hash))
                        {
                            // send data to the searcher of this key

                            try
                            {
                                // get the value
                                InputStreamReader isreader = new InputStreamReader(getContext().openFileInput(key));
                                BufferedReader br = new BufferedReader(isreader);
                                String value = br.readLine();

                                // send data to source
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), received_obj.port_sender));
                                Message msg_to_send = new Message();
                                msg_to_send.port_sender = current_port;
                                msg_to_send.message_id = MessageType.FOUND_DATA;
                                msg_to_send.key = key;
                                msg_to_send.value = value;

                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(msg_to_send);
                                socket.close();
                                Log.v("FOUND_DATA " + key, current_port + " " + value);
                            }
                            catch (Exception e)
                            {
                                Log.v("Exception in find in server ", key);
                            }
                        }
                        else
                        {
                            // send data to next avd
                            Log.v("FIND_REQUEST_FORWARDED " + received_obj.key, sucessor_port + "");
                            try
                            {
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(received_obj);
                                socket.close();
                            }
                            catch (Exception e)
                            {

                            }
                        }
                    }
                    else if(received_obj.message_id == MessageType.NODE_JOIN_REQUEST)
                    {
                        Log.v("JOIN_REQUEST", "got join request from " + received_obj.port_sender);
                        Log.v("MY_SUCCESSOR_PREDECESSOR", sucessor_port + " " + predecessor_port);

                        try
                        {
                            String sender_hash = genHash((received_obj.port_sender/2) + "");
                            if( predecessor_port == current_port ||
                                    (isBetween(predecessor_id, node_id, sender_hash)))
                            {
                                // msg sent to update successor of new node
                                Message msg_to_update_sucessor = new Message();
                                msg_to_update_sucessor.port_sender = current_port;
                                msg_to_update_sucessor.message_id = MessageType.UPDATE_SUCESSOR;
                                msg_to_update_sucessor.data = current_port;

                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), received_obj.port_sender));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(msg_to_update_sucessor);
                                socket.close();

                                // msg sent to update predecessor of new node
                                Message msg_to_update_predecessor = new Message();
                                msg_to_update_predecessor.port_sender = current_port;
                                msg_to_update_predecessor.message_id = MessageType.UPDATE_PREDECESSOR;
                                msg_to_update_predecessor.data = predecessor_port;

                                socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), received_obj.port_sender));
                                oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(msg_to_update_predecessor);
                                socket.close();

                                // msg sent to update successor of this node's predecessor
                                socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), predecessor_port));
                                oos = new ObjectOutputStream(socket.getOutputStream());
                                msg_to_update_sucessor.data = received_obj.port_sender;
                                oos.writeObject(msg_to_update_sucessor);
                                socket.close();

                                // updating predecessor of this current node
                                predecessor_port = received_obj.port_sender;
                                predecessor_id = genHash((predecessor_port/2) + "");
                            }
                            else
                            {
                                Log.v("FORWARD_NODE_JOIN_REQEST", "" + sucessor_port);
                                Log.v("REASON", sender_hash + " not between " + predecessor_port + current_port);
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(received_obj);
                                socket.close();
                            }
                        }
                        catch (Exception e)
                        {

                        }
                    }
                    else if(received_obj.message_id == MessageType.UPDATE_PREDECESSOR)
                    {
                        predecessor_port = received_obj.data;
                        predecessor_id = genHash((predecessor_port/2) + "");
                        Log.v("PREDECESSOR_UPDATE", predecessor_port + "");
                    }
                    else if(received_obj.message_id == MessageType.UPDATE_SUCESSOR)
                    {
                        sucessor_port = received_obj.data;
                        sucessor_id = genHash((sucessor_port/2) + "");
                        Log.v("SUCESSOR_UPDATE", sucessor_port + "");
                    }
                    else if(received_obj.message_id == MessageType.DELETE_DATA)
                    {
                        String key = received_obj.key;

                        if(key.equals("\"*\""))
                        {
                            File data_files_dir = getContext().getFilesDir();
                            File [] all_files = data_files_dir.listFiles();

                            for(File file : all_files)
                            {
                                String path = file.getPath();
                                getContext().deleteFile(path);
                            }

                            if(received_obj.port_sender != current_port)
                            {
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(received_obj);
                                socket.close();
                            }
                        }
                        else if(isBetween(predecessor_id, node_id, key))
                        {
                            // insert key and value in the current avd
                            publishProgress("DELETE", key, received_obj.value);
                        }
                        else
                        {
                            // send data to next avd
                            try
                            {
                                Socket socket = new Socket();
                                socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), sucessor_port));
                                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                                oos.writeObject(received_obj);
                                socket.close();
                            }
                            catch (Exception e)
                            {

                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }

            return null;
        }

        @Override
        protected void onProgressUpdate(String... values)
        {
            super.onProgressUpdate(values);

            if(values[0].equals("INSERT"))
            {
                try
                {
                    FileOutputStream fos = getContext().openFileOutput(values[1], Context.MODE_PRIVATE);
                    fos.write(values[2].getBytes());
                    fos.close();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }

                Log.v("DATA_INSERTED", values[1] + " in " + current_port);
            }

            if(values[0].equals("DELETE"))
            {
                try
                {
                    getContext().deleteFile(values[1]);
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }

                Log.v("DATA_DELETED", values[1] + " in " + current_port);
            }
        }
    }
}
