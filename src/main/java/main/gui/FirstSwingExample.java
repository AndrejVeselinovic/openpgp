package main.gui;

import main.OpenPGP;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.dtos.UserKeyInfo;
import main.repositories.FileRepository;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class FirstSwingExample {
	private static final OpenPGP OPENPGP_CLIENT = new OpenPGP(new FileRepository());
	private static final int WINDOW_HEIGHT = 600;
	private static final int WINDOW_WIDTH = 800;
	private static final int LOCATION_X = 500;
	private static final int LOCATION_Y = 300;

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
		JButton generateKeyPairButton = getGenerateKeyPairButton();
//		generateKeyPairButton.setSize(new Dimension(200, 50));
		buttonPanel.add(generateKeyPairButton);
		buttonPanel.add(getEncryptMessageButton());
		buttonPanel.add(getDecryptMessageButton());
		return buttonPanel;
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

		JList<KeyPairAlgorithm> signingAlgorithms = new JList<>(KeyPairAlgorithm.getSigningAlgorithms());
		panel.add(signingAlgorithms);
		JList<KeyPairAlgorithm> encryptionAlgorithms = new JList<>(KeyPairAlgorithm.getEncryptionAlgorithms());
		panel.add(encryptionAlgorithms);

		dialog.add(panel);
		dialog.setSize((int) (WINDOW_WIDTH * 0.6), (int) (WINDOW_HEIGHT * 0.6));
		dialog.setLocation((int) (LOCATION_X * 1.2), (int) (LOCATION_Y * 1.2));

		JPanel buttonPanel = new JPanel();

		buttonPanel.add(getGenerateKeyPairDialogButton());

		dialog.add(buttonPanel, BorderLayout.SOUTH);
		return dialog;
	}

	private static JButton getGenerateKeyPairDialogButton(){
		JButton generateButton = new JButton("Generate");

		generateButton.addActionListener(e -> refreshMainPanel());
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
		return new JButton("Encrypt");
	}

	private static JButton getDecryptMessageButton(){
		return new JButton("Decrypt");
	}

	private static JScrollPane getUsersTable(boolean clickable) {
		String[] columnNames = new String[]{"Name", "Email", "Signing Key Type", "Encryption Key Type", "ID"};
		List<UserKeyInfo> userKeys = OPENPGP_CLIENT.getUserKeys();
		String[][] data = new String[userKeys.size()][columnNames.length];
		for (int i = 0; i < userKeys.size(); i++) {
			UserKeyInfo currentUserKey = userKeys.get(i);
			data[i][0] = currentUserKey.getUsername();
			data[i][1] = currentUserKey.getEmail();
			data[i][2] = currentUserKey.getSignatureKeyType().name();
			data[i][3] = currentUserKey.getEncryptionKeyType().name();
			data[i][4] = currentUserKey.getKeyId().toString();
		}

		JTable table = new JTable(data, columnNames) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		TableColumnModel columnModel = table.getColumnModel();
		columnModel.removeColumn(columnModel.getColumn(columnNames.length - 1));

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