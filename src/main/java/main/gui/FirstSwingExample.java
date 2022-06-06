package main.gui;

import main.OpenPGP;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.dtos.UserKeyInfo;
import main.repositories.FileRepository;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static javax.swing.JOptionPane.showMessageDialog;

public class FirstSwingExample {
	private static final OpenPGP OPENPGP_CLIENT = new OpenPGP(new FileRepository());
	private static final int WINDOW_HEIGHT = 600;
	private static final int WINDOW_WIDTH = 800;
	private static final int LOCATION_X = 500;
	private static final int LOCATION_Y = 300;

	private static final String PATH_TO_KEYS_DIR = "D:/Nedim/ZP/openpgp/keys";

	private static JFrame frame;
	private static JScrollPane usersPanel;

	public static void main(String[] args) {
		frame = getMainFrame();

		refreshMainPanel();

		frame.setSize(WINDOW_WIDTH, WINDOW_HEIGHT);
		frame.setLocation(LOCATION_X, LOCATION_Y);
		frame.setVisible(true);
	}

	private static JFrame getMainFrame() {
		JFrame frame = new JFrame();
		frame.addWindowListener(new java.awt.event.WindowAdapter() {
			@Override
			public void windowClosing(java.awt.event.WindowEvent windowEvent) {
				if (JOptionPane.showConfirmDialog(frame,
						"Are you sure you want to close this window?", "Close Window?",
						JOptionPane.YES_NO_OPTION,
						JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION){
					System.exit(0);
				}
			}
		});
		return frame;
	}

	private static JPanel getButtonsPanel() {
		JPanel buttonPanel = new JPanel();

		buttonPanel.add(getGenerateKeyPairButton());
		buttonPanel.add(getDeletePrivateKeyButton());
		buttonPanel.add(getEncryptMessageButton());
		buttonPanel.add(getDecryptMessageButton());
		buttonPanel.add(getImportButton());
		buttonPanel.add(getExportButton());
		return buttonPanel;
	}

	private static JButton getExportButton() {
		JButton exportButton = new JButton("Export");
		JDialog dialog = getGenerateKeyPairDialog();
		exportButton.addActionListener(event -> dialog.setVisible(true));
		return exportButton;
	}

	private static JButton getImportButton() {
		JButton importButton = new JButton("Import");
		JDialog dialog = getDeletePrivateKeyDialog();
		importButton.addActionListener(event -> dialog.setVisible(true));
		return importButton;
	}

	private static JButton getDeletePrivateKeyButton() {
		JButton deletePrivateKeyButton = new JButton("Delete Private Key");
		JDialog dialog = getDeletePrivateKeyDialog();
		deletePrivateKeyButton.addActionListener(event -> dialog.setVisible(true));
		return deletePrivateKeyButton;
	}

	private static JDialog getDeletePrivateKeyDialog() {
		JDialog dialog = new JDialog();
		JPanel panel = new JPanel();

		JTextField passwordTextField = new JTextField(20);
		panel.add(passwordTextField);

		JPanel buttonPanel = new JPanel();
		JButton submitDeleteButton = new JButton("Submit");
		buttonPanel.add(submitDeleteButton);

		submitDeleteButton.addActionListener(e -> {
			JViewport viewport = usersPanel.getViewport();
			JTable table = (JTable)viewport.getView();

			int selectedRow = table.getSelectedRow();
			if (selectedRow == -1){
				showMessageDialog(null, "Select row to delete");
				return;
			}

			String keyId = (String) table.getModel().getValueAt(selectedRow, 4);
			String password = (String) table.getModel().getValueAt(selectedRow, 5);

			if (!password.equals(passwordTextField.getText())){
				showMessageDialog(null, "Wrong password!");
				return;
			}

			OPENPGP_CLIENT.deleteKeyPair(UUID.fromString(keyId));

			refreshMainPanel();
		});

		dialog.add(buttonPanel, BorderLayout.SOUTH);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.4), (int) (WINDOW_HEIGHT * 0.4));
		dialog.setLocation((int) (LOCATION_X * 1.4), (int) (LOCATION_Y * 1.2));

		return dialog;
	}

	private static JButton getGenerateKeyPairButton() {
		JButton generateKeyPairButton = new JButton("Generate New Key Pair");
		JDialog dialog = getGenerateKeyPairDialog();
		generateKeyPairButton.addActionListener(event -> dialog.setVisible(true));
		return generateKeyPairButton;
	}

	private static JDialog getGenerateKeyPairDialog() {
		JDialog dialog = new JDialog();
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

		JPanel emailPanel = new JPanel();
		JLabel emailLabel = new JLabel("Email: ");
		JTextField emailTextField = new JTextField(20);
		emailPanel.add(emailLabel);
		emailPanel.add(emailTextField);


		JPanel usernamePanel = new JPanel();
		JLabel usernameLabel = new JLabel("Username: ");
		JTextField usernameTextField = new JTextField(20);
		usernamePanel.add(usernameLabel);
		usernamePanel.add(usernameTextField);

		JPanel signingAlgPanel = new JPanel();
		JLabel signingAlLabel = new JLabel("Signing algorithm");
		JComboBox<KeyPairAlgorithm> signingAlgorithms = new JComboBox<>(KeyPairAlgorithm.getSigningAlgorithms());
		signingAlgPanel.add(signingAlLabel);
		signingAlgPanel.add(signingAlgorithms);

		JPanel ecnryptAlgPanel = new JPanel();
		JLabel encryptAlLabel = new JLabel("Encryption algorithm");
		JComboBox<KeyPairAlgorithm> encryptionAlgorithms = new JComboBox<>(KeyPairAlgorithm.getEncryptionAlgorithms());
		ecnryptAlgPanel.add(encryptAlLabel);
		ecnryptAlgPanel.add(encryptionAlgorithms);


		JPanel passwordPKPanel = new JPanel();
		JLabel passwordPKLabel = new JLabel("PasswordPK: ");
		JTextField passwordPKTextField = new JTextField(20);
		passwordPKPanel.add(passwordPKLabel);
		passwordPKPanel.add(passwordPKTextField);

		panel.add(emailPanel);
		panel.add(usernamePanel);
		panel.add(signingAlgPanel);
		panel.add(ecnryptAlgPanel);
		panel.add(passwordPKPanel);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.6), (int) (WINDOW_HEIGHT * 0.6));
		dialog.setLocation((int) (LOCATION_X * 1.2), (int) (LOCATION_Y * 1.2));

		JPanel buttonPanel = new JPanel();

		buttonPanel.add(getGenerateKeyPairDialogButton(usernameTextField, emailTextField, passwordPKTextField,
				encryptionAlgorithms, signingAlgorithms));

		dialog.add(buttonPanel, BorderLayout.SOUTH);
		return dialog;
	}

	private static JButton getGenerateKeyPairDialogButton(JTextField usernameTextField,
														  JTextField emailTextField,
														  JTextField passwordPKTextField,
														  JComboBox<KeyPairAlgorithm> encryptionAlgorithms,
														  JComboBox<KeyPairAlgorithm> signingAlgorithms){
		JButton generateButton = new JButton("Generate");

		generateButton.addActionListener(e -> {
			if (
					Objects.equals(usernameTextField.getText(), "")
							|| Objects.equals(emailTextField.getText(), "")
							|| Objects.equals(passwordPKTextField.getText(), "")
							|| encryptionAlgorithms.getSelectedItem() == null
							|| signingAlgorithms.getSelectedItem() == null)
			{
				showMessageDialog(null, "All fields should be filled!");
			}
			else{
				OPENPGP_CLIENT.generateKeyPair(usernameTextField.getText(), emailTextField.getText(),
						passwordPKTextField.getText(), (KeyPairAlgorithm) signingAlgorithms.getSelectedItem(),
						(KeyPairAlgorithm) encryptionAlgorithms.getSelectedItem());
				refreshMainPanel();
			}
		});
		return generateButton;
	}

	private static void refreshMainPanel() {
		Container mainPanel = frame.getContentPane();

		if (usersPanel != null) {
			usersPanel.removeAll();
			mainPanel.remove(usersPanel);
		}

		usersPanel = getUsersTable(false);
		mainPanel.add(usersPanel, BorderLayout.CENTER);

		JPanel buttonsPanel = getButtonsPanel();
		buttonsPanel.setSize(WINDOW_WIDTH, (int) (WINDOW_HEIGHT * 0.3));
		mainPanel.add(buttonsPanel, BorderLayout.NORTH);

		frame.revalidate();
		frame.repaint();
		System.out.println("refreshed");
	}

	private static JButton getEncryptMessageButton() {
		JButton encryptButton = new JButton("Encrypt");
		JDialog dialog = getGenerateEncryptDialog();
		encryptButton.addActionListener(event -> dialog.setVisible(true));
		return encryptButton;
	}

	private static JDialog getGenerateEncryptDialog() {
		JDialog dialog = new JDialog();
		dialog.setTitle("Encrypt message");

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

		JPanel messageTextAreaPanel = new JPanel();
		JTextArea messageTextArea = new JTextArea(40, 40);
		messageTextAreaPanel.add(messageTextArea);
		panel.add(messageTextAreaPanel);

		JPanel encryptPanel = new JPanel();
		JTextField encryptTextField = new JTextField(30);
		encryptTextField.setEditable(false);
		JButton providePrivacyButton= new JButton("Encryption");
		encryptPanel.add(providePrivacyButton);
		encryptPanel.add(encryptTextField);

		providePrivacyButton.addActionListener(e -> {
			JFileChooser chooser = new JFileChooser(PATH_TO_KEYS_DIR);
			if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if(!selectedFile.getName().endsWith(".pub.asc")){
					showMessageDialog(null, "Choose public key!");
					return;
				}
				encryptTextField.setText(selectedFile.getName());
			}
		});
		panel.add(encryptPanel);


		JPanel authPanel = new JPanel();
		JTextField signAuthTextField = new JTextField(30);
		signAuthTextField.setEditable(false);
		JButton signAuthButton = new JButton("Authentication");
		authPanel.add(signAuthButton);
		authPanel.add(signAuthTextField);
		panel.add(authPanel);

		JPanel passwordPKPanel = new JPanel();
		JLabel passwordLabel = new JLabel("Password");
		passwordPKPanel.add(passwordLabel);
		JTextField passwordTextField = new JTextField(20);
		passwordPKPanel.add(passwordTextField);
		panel.add(passwordPKPanel);

		signAuthButton.addActionListener(e -> {
			JFileChooser chooser = new JFileChooser(PATH_TO_KEYS_DIR);
			if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if(!selectedFile.getName().endsWith(".priv.asc")){
					showMessageDialog(null, "Choose private key!");
					return;
				}
				UUID keyId = UUID.fromString(
						selectedFile.getName().split("\\.")[0]);
				if(!passwordTextField.getText().equals(OPENPGP_CLIENT.getPasswordForKeyId(keyId))){
					showMessageDialog(null, "Wrong password for chosen private key!");
					return;
				}

				signAuthTextField.setText(selectedFile.getName());
			}
		});


		JPanel signignAlgorithmPanel = new JPanel();
		JLabel signingAlhoritmLabel = new JLabel("Signing algorithm: ");
		signignAlgorithmPanel.add(signingAlhoritmLabel);
		JComboBox<KeyPairAlgorithm> signingAlgorithms = new JComboBox<>(KeyPairAlgorithm.getSigningAlgorithms());
		signignAlgorithmPanel.add(signingAlgorithms);
		panel.add(signignAlgorithmPanel);

		JPanel encryptAlgorithmPanel = new JPanel();
		JLabel encryptAlgorithmLabel = new JLabel("Encryption algorithm: ");
		encryptAlgorithmPanel.add(encryptAlgorithmLabel);
		JComboBox<KeyPairAlgorithm> encryptAlgorithms = new JComboBox<>(KeyPairAlgorithm.getEncryptionAlgorithms());
		encryptAlgorithmPanel.add(encryptAlgorithms);
		panel.add(encryptAlgorithmPanel);


		JPanel checkBoxPanel = new JPanel();
		JCheckBox compressCheckBox = new JCheckBox("Compress");
		checkBoxPanel.add(compressCheckBox);

		JCheckBox radix64CheckBox = new JCheckBox("Radix64");
		checkBoxPanel.add(radix64CheckBox);
		panel.add(checkBoxPanel);

		JButton submitButton = new JButton("Submit");
//		submitButton.addActionListener(e -> {
//			String message = messageTextArea.getText();
//			if (message == null || message.equals("")){
//				showMessageDialog(null, "Message is empty! Nothing to encrypt.");
//				return;
//			}
//
//			boolean shouldCompress = compressCheckBox.isSelected();
//			boolean shouldEncode = radix64CheckBox.isSelected();
//			UUID publicKeyUUID = UUID.fromString(encryptTextField.getText().split("\\.")[0]);
//			UUID privateKeyUUID = UUID.fromString(signAuthTextField.getText().split("\\.")[0]);
//			KeyPairAlgorithm encryptionAlgorithm = (KeyPairAlgorithm) encryptAlgorithms.getSelectedItem();
//			KeyPairAlgorithm signingAlgorithm = (KeyPairAlgorithm) signingAlgorithms.getSelectedItem();
//
//			OPENPGP_CLIENT.encrypt(message, publicKeyUUID, encryptionAlgorithm.getAsymmetricStrategy(), shouldCompress,
//					privateKeyUUID, );
//		});
		panel.add(submitButton);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.8), (int) (WINDOW_HEIGHT * 0.7));
		dialog.setLocation((int) (LOCATION_X * 1.4), (int) (LOCATION_Y * 1.2));

		return dialog;
	}

	private static JButton getDecryptMessageButton(){
		return new JButton("Decrypt");
	}

	private static JScrollPane getUsersTable(boolean clickable) {
		String[] columnNames = new String[]{"Name", "Email", "Signing Key Type", "Encryption Key Type", "ID", "Password"};
		List<UserKeyInfo> userKeys = OPENPGP_CLIENT.getUserKeys();
		String[][] data = new String[userKeys.size()][columnNames.length];
		for (int i = 0; i < userKeys.size(); i++) {
			UserKeyInfo currentUserKey = userKeys.get(i);
			data[i][0] = currentUserKey.getUsername();
			data[i][1] = currentUserKey.getEmail();
			data[i][2] = currentUserKey.getSignatureKeyType().name();
			data[i][3] = currentUserKey.getEncryptionKeyType().name();
			data[i][4] = currentUserKey.getKeyId().toString();
			data[i][5] = currentUserKey.getPassword();
		}

		JTable table = new JTable(data, columnNames) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		TableColumnModel columnModel = table.getColumnModel();
		columnModel.removeColumn(columnModel.getColumn(columnNames.length - 1));
		columnModel.removeColumn(columnModel.getColumn(columnNames.length - 2));

		table.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent mouseEvent) {
				JTable table =(JTable) mouseEvent.getSource();
				Point point = mouseEvent.getPoint();
				if (mouseEvent.getClickCount() == 2 && table.getSelectedRow() != -1) {
					int row = table.rowAtPoint(point);
					String keyId = data[row][columnNames.length - 1];
					System.out.println(keyId);
				}
			}
		});

		table.setSize(WINDOW_WIDTH, (int) (WINDOW_HEIGHT * 0.7));
		return new JScrollPane(table, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
	}
}