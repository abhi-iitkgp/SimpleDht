package edu.buffalo.cse.cse486586.simpledht;

import java.io.Serializable;
import java.util.HashMap;

/**
 * Created by abhinav on 3/24/15.
 */
public class Message implements Serializable
{
    MessageType message_id;
    int port_sender;
    String key;
    String value;
    int data;
    HashMap<String, String> key_value_data = new HashMap<String, String>();
}

enum MessageType
{
    NODE_JOIN_REQUEST,
    FIND,
    ADD_DATA,
    DELETE_DATA,
    UPDATE_PREDECESSOR,
    UPDATE_SUCESSOR,
    FOUND_DATA
}
