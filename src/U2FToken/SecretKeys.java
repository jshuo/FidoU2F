package U2FToken;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/** 
 * @author Yang Zhou 
 * @version ����ʱ�䣺2015-12-10 ����06:51:23 
 * ����Կ��صĲ��������ݷ�װ��
 */
public class SecretKeys {
	
	public static final byte MODE_ENCRYPT = 0x01; // ����ģʽ
	public static final byte MODE_DECRYPT = 0x02; // ����ģʽ
	
	public static final byte KEY_TYPE_AES = 0x01; // ��ʾ���������AES��Կ
	public static final byte KEY_TYPE_DES = 0x02; // ��ʾ���������DES��Կ
	
//	private byte mKeyType = 0x00;
	
	/**
	 * ��Կ��ʵ�壬DES
	 */
//	private DESKey mDESKeyInstance = null;
	
	/**
	 * ��Կ��ʵ�壬AES
	 */
	private AESKey mAESKeyInstance = null;
	
	/**
	 * ��ʼ��key wrap�㷨����Կ
	 * ����AES-256�����ɵ�AES��Կ��256λ
	 * ����DES3-2KEY�����ɵ�DES��Կ��128λ
	 */
	public SecretKeys(byte keyType) {
//		mKeyType = keyType;
//		if (mKeyType == KEY_TYPE_DES) {
////			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
//			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
//			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
//			mDESKeyInstance.setKey(keyData, (short) 0);
//		} else if (mKeyType == KEY_TYPE_AES) {
			try {
				// TODO �����е����⣬û������㷨��
				mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			} catch(CryptoException e) {
//				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
//			mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			// TODO �ǲ��������д�����������AES-256Ӧ����32�ֽڣ���
			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
			mAESKeyInstance.setKey(keyData, (short) 0);
//		} else {
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//		}
		
	}
	
	/**
	 * key wrap�㷨��������� AES-256 �� ALG_AES_BLOCK_128_CBC_NOPAD
	 * @param data ��Ҫ wrap ������
	 * @param inOffset
	 * @param inLength
	 * @param outBuff
	 * @param outOffset
	 * @param mode ���ܻ���ܡ� Cipher.MODE_ENCRYPT �� Cipher.MODE_DECRYPT
	 */
	public void keyWrap(byte[] data, short inOffset, short inLength, byte[] buffer, short outOffset, byte mode) {
		Cipher cipher = null;
//		if (mKeyType == KEY_TYPE_DES) {
////			cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
//			cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
//			cipher.init(mDESKeyInstance, mode); // ��ʼ����(iv)��0
//		} else if (mKeyType == KEY_TYPE_AES) {
//			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			try {
				// Cipher.getInstance����������ˣ���U2FToken���ܹ�������
				cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			} catch (CryptoException e) {
				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
			cipher.init(mAESKeyInstance, mode); // ��ʼ����(iv)��0
//		}
		
		// ���ܻ���ܣ�doFinal��cipher���󽫱�����
		try {
			cipher.doFinal(data, inOffset, inLength, buffer, outOffset);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
}
