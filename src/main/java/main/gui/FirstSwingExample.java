package main.gui;

import main.OpenPGP;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.algorithms.symmetric.EncryptionAlgorithm;
import main.dtos.UserKeyInfo;
import main.repositories.FileRepository;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static javax.swing.JOptionPane.showMessageDialog;

public class FirstSwingExample {
	private static final OpenPGP OPENPGP_CLIENT = new OpenPGP(new FileRepository());
	private static final int WINDOW_HEIGHT = 600;
	private static final int WINDOW_WIDTH = 800;
	private static final int LOCATION_X = 500;
	private static final int LOCATION_Y = 300;

	private static final String PATH_TO_KEYS_DIR = "D:/Nedim/ZP/openpgp/keys";


	private static final String[] columnNames = new String[]{"Name", "Email", "Signing Key Type", "Encryption Key Type", "ID", "Password"};
	private static final int IdColumnIndex = columnNames.length - 2;
	private static String[][] data;
	private static final AtomicReference<Collection<UUID>> publicKeysForEncryption = new AtomicReference<>();
	private static final AtomicReference<UUID> privateKey = new AtomicReference<>();
	private static final AtomicReference<String> privateKeyPassword = new AtomicReference<>();
	private static JFrame frame;
	private static JScrollPane usersPanel;

	static {
		updateData();
	}

	private static void updateData() {
		List<UserKeyInfo> userKeys = OPENPGP_CLIENT.getUserKeys();
		data = new String[userKeys.size()][columnNames.length];
		for (int i = 0; i < userKeys.size(); i++) {
			UserKeyInfo currentUserKey = userKeys.get(i);
			data[i][0] = currentUserKey.getUsername();
			data[i][1] = currentUserKey.getEmail();
			data[i][2] = currentUserKey.getSignatureKeyType().name();
			data[i][3] = currentUserKey.getEncryptionKeyType().name();
			data[i][4] = currentUserKey.getKeyId().toString();
			data[i][5] = currentUserKey.getPassword();
		}
	}
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
				System.exit(0);
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

		JPanel encryptAlgPanel = new JPanel();
		JLabel encryptAlLabel = new JLabel("Encryption algorithm");
		JComboBox<KeyPairAlgorithm> encryptionAlgorithms = new JComboBox<>(KeyPairAlgorithm.getEncryptionAlgorithms());
		encryptAlgPanel.add(encryptAlLabel);
		encryptAlgPanel.add(encryptionAlgorithms);


		JPanel passwordPKPanel = new JPanel();
		JLabel passwordPKLabel = new JLabel("PasswordPK: ");
		JTextField passwordPKTextField = new JTextField(20);
		passwordPKPanel.add(passwordPKLabel);
		passwordPKPanel.add(passwordPKTextField);

		panel.add(emailPanel);
		panel.add(usernamePanel);
		panel.add(signingAlgPanel);
		panel.add(encryptAlgPanel);
		panel.add(passwordPKPanel);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.6), (int) (WINDOW_HEIGHT * 0.6));
		dialog.setLocation((int) (LOCATION_X * 1.2), (int) (LOCATION_Y * 1.2));

		JPanel buttonPanel = new JPanel();

		buttonPanel.add(getGenerateKeyPairDialogButton(usernameTextField, emailTextField, passwordPKTextField,
				encryptionAlgorithms, signingAlgorithms, dialog));

		dialog.add(buttonPanel, BorderLayout.SOUTH);
		return dialog;
	}

	private static JButton getGenerateKeyPairDialogButton(JTextField usernameTextField,
														  JTextField emailTextField,
														  JTextField passwordPKTextField,
														  JComboBox<KeyPairAlgorithm> encryptionAlgorithms,
														  JComboBox<KeyPairAlgorithm> signingAlgorithms,
			JDialog dialog){
		JButton generateButton = new JButton("Generate");

		generateButton.addActionListener(e -> {
			if (
					Objects.equals(usernameTextField.getText(), "")
							|| Objects.equals(emailTextField.getText(), "")
							|| Objects.equals(passwordPKTextField.getText(), "")
							|| encryptionAlgorithms.getSelectedItem() == null
							|| signingAlgorithms.getSelectedItem() == null)
			{
				showMessageDialog(dialog, "All fields should be filled!");
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

		usersPanel = getUsersPanel();
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

		JButton providePrivacyButton= new JButton("Select Public Keys");
		encryptPanel.add(providePrivacyButton);
		providePrivacyButton.addActionListener(event -> new Thread(FirstSwingExample::getUsersTableForEncryption).start());
		panel.add(encryptPanel);

		JButton signAuthButton = new JButton("Select Private Key To Sign With");
		signAuthButton.addActionListener(event -> new Thread(FirstSwingExample::getUsersTablePrivateKeyInput).start());
		panel.add(signAuthButton);

		JPanel authPanel = new JPanel();
		panel.add(authPanel);

		JLabel encryptionAlgorithmLabel = new JLabel("Encryption Algorithm:");
		authPanel.add(encryptionAlgorithmLabel);

		JComboBox<EncryptionAlgorithm> encryptionAlgorithms = new JComboBox<>(EncryptionAlgorithm.getEncryptionAlgorithms());
		encryptionAlgorithms.setSize(100, 20);
		authPanel.add(encryptionAlgorithms);

		JPanel checkBoxPanel = new JPanel();
		JCheckBox compressCheckBox = new JCheckBox("Compress");
		checkBoxPanel.add(compressCheckBox);

		JCheckBox radix64CheckBox = new JCheckBox("Radix64");
		checkBoxPanel.add(radix64CheckBox);
		panel.add(checkBoxPanel);

		JTextField encryptedMessageFilePath = new JTextField("File path");
		panel.add(encryptedMessageFilePath);

		JButton submitButton = new JButton("Submit");
		submitButton.addActionListener(event -> {
			byte[] encryptedBytes = OPENPGP_CLIENT.encrypt(
					messageTextArea.getText(),
					publicKeysForEncryption.get(),
					(EncryptionAlgorithm) Objects.requireNonNull(encryptionAlgorithms.getSelectedItem()),
					compressCheckBox.isSelected(),
					privateKey.get(),
					privateKeyPassword.get(),
					radix64CheckBox.isSelected());
			OpenPGP.flushToFile(encryptedBytes, encryptedMessageFilePath.getText());
		});
		panel.add(submitButton);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.8), (int) (WINDOW_HEIGHT * 0.7));
		dialog.setLocation((int) (LOCATION_X * 1.4), (int) (LOCATION_Y * 1.2));

		return dialog;
	}


	private static JButton getDecryptMessageButton(){
		return new JButton("Decrypt");
	}

	private static JScrollPane getUsersPanel() {
		return new JScrollPane(getUsersTable(), JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
	}

	private static JTable getUsersTable() {
		updateData();
		JTable table = new JTable(data, columnNames) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		TableColumnModel columnModel = table.getColumnModel();
		columnModel.removeColumn(columnModel.getColumn(columnNames.length - 1));
		columnModel.removeColumn(columnModel.getColumn(columnNames.length - 2));
		table.setSize(WINDOW_WIDTH, (int) (WINDOW_HEIGHT * 0.7));
		return table;
	}

	private static void getUsersTableForEncryption() {
		JDialog dialog = new JDialog();

		JTable table = getUsersTable();
		dialog.add(table, BorderLayout.CENTER);

		JButton submitButton = new JButton("Choose");
		submitButton.addActionListener(event->{
			List<UUID> publicKeys = Arrays.stream(table.getSelectedRows())
					.mapToObj(selectedRow -> data[selectedRow][columnNames.length - 2])
					.map(UUID::fromString)
					.collect(Collectors.toList());
			publicKeysForEncryption.set(publicKeys);
			dialog.dispose();
		});
		dialog.add(submitButton, BorderLayout.SOUTH);

		dialog.setSize((int) (WINDOW_WIDTH * 0.8), (int) (WINDOW_HEIGHT * 0.8));
		dialog.setLocation((int) (LOCATION_X * 1.4), (int) (LOCATION_Y * 1.2));
		dialog.setVisible(true);
	}

	private static void getUsersTablePrivateKeyInput() {
		JDialog dialog = new JDialog();
		JPanel panel = new JPanel();
		dialog.add(panel);

		JTable table = getUsersTable();
		table.setPreferredSize(new Dimension(300, 500));
		panel.add(table, BorderLayout.CENTER);

		JLabel passwordLabel = new JLabel("Enter Password:");
		passwordLabel.setVisible(true);
		panel.add(passwordLabel, BorderLayout.SOUTH);

		JTextField passwordTextField = new JTextField();
		passwordTextField.setSize(200, 50);
		passwordTextField.setVisible(true);
		panel.add(passwordTextField, BorderLayout.SOUTH);

		JButton submitButton = new JButton("Choose");
		submitButton.addActionListener(event->{
			int selectedRow = table.getSelectedRow();
			if(selectedRow == -1) {
				return;
			}
			String uuidString = data[selectedRow][IdColumnIndex];
			UUID privateKeyId = UUID.fromString(uuidString);

			String realPassword = OPENPGP_CLIENT.getPasswordForKeyId(privateKeyId);
			boolean passwordsMatch = realPassword.equals(passwordTextField.getText());
			if(passwordsMatch) {
				privateKey.set(privateKeyId);
				privateKeyPassword.set(realPassword);
				dialog.dispose();
			} else {
				showMessageDialog(dialog, "Invalid Password!");
			}
		});
		panel.add(submitButton, BorderLayout.SOUTH);

		dialog.setSize((int) (WINDOW_WIDTH * 0.8), (int) (WINDOW_HEIGHT * 0.8));
		dialog.setLocation((int) (LOCATION_X * 1.4), (int) (LOCATION_Y * 1.2));
		dialog.setVisible(true);
	}
}