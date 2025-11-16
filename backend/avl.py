"""
Módulo AVL
Implementa árvore AVL para operações de inserção e busca em O(log n).

Contém:
- Classe AVLNode: representa um nó da árvore.
- Classe AVLTree: representa a estrutura completa, com inserção balanceada,
  rotações e busca eficiente.

Esta estrutura é usada no sistema para armazenar e buscar incidentes de forma
performática, atendendo aos requisitos da GS.
"""


class AVLNode:
    """
    Representa um nó individual da árvore AVL.

    Atributos:
        key: chave usada para ordenação e busca.
        value: valor associado à chave.
        left (AVLNode): filho à esquerda.
        right (AVLNode): filho à direita.
        height (int): altura do nó na árvore.

    Usado internamente pela AVLTree.
    """

    def __init__(self, key, value):
        """
        Inicializa um nó AVL.

        Args:
            key: chave única do nó.
            value: valor associado à chave.
        """
        self.key = key
        self.value = value
        self.left = None
        self.right = None
        self.height = 1


class AVLTree:
    """
    Implementa uma Árvore AVL completa, com inserção e busca em O(log n).

    Métodos principais:
        insert(key, value): insere ou substitui um elemento.
        search(key): retorna (value, key) ou (None, None).
        inorder(): retorna lista ordenada (key, value).

    A estrutura se auto-balanceia por meio de rotações.
    """

    def __init__(self):
        """Inicializa a árvore AVL vazia."""
        self.root = None

    # UTILITÁRIAS INTERNAS

    def _height(self, node):
        """
        Retorna a altura de um nó.

        Args:
            node (AVLNode): nó cujo tamanho será retornado.

        Returns:
            int: altura do nó, ou 0 se None.
        """
        return node.height if node else 0

    def _update_height(self, node):
        """
        Atualiza a altura de um nó com base em seus filhos.

        Args:
            node (AVLNode): nó a ser atualizado.
        """
        if node:
            node.height = 1 + max(self._height(node.left),
                                  self._height(node.right))

    def _balance_factor(self, node):
        """
        Retorna o fator de balanceamento do nó.

        Args:
            node (AVLNode)

        Returns:
            int: diferença entre alturas da subárvore esquerda e direita.
        """
        return self._height(node.left) - self._height(node.right) if node else 0

    def _rotate_right(self, y):
        """
        Realiza rotação simples à direita (Right Rotation).

        Args:
            y (AVLNode): nó desbalanceado.

        Returns:
            AVLNode: novo nó raiz após rotação.
        """
        x = y.left
        T2 = x.right

        x.right = y
        y.left = T2

        self._update_height(y)
        self._update_height(x)

        return x

    def _rotate_left(self, x):
        """
        Realiza rotação simples à esquerda (Left Rotation).

        Args:
            x (AVLNode): nó desbalanceado.

        Returns:
            AVLNode: novo nó raiz após rotação.
        """
        y = x.right
        T2 = y.left

        y.left = x
        x.right = T2

        self._update_height(x)
        self._update_height(y)

        return y

    # INSERÇÃO PÚBLICA

    def insert(self, key, value):
        """
        Insere um par (key, value) na AVL.

        A operação é automaticamente balanceada para manter O(log n).

        Args:
            key: chave de ordenação.
            value: valor armazenado.
        """
        self.root = self._insert(self.root, key, value)

    def _insert(self, node, key, value):
        """
        Inserção recursiva interna com balanceamento.

        Args:
            node (AVLNode): nó atual.
            key: chave a ser inserida.
            value: valor associado.

        Returns:
            AVLNode: nó já balanceado.
        """
        if node is None:
            return AVLNode(key, value)

        if key < node.key:
            node.left = self._insert(node.left, key, value)
        elif key > node.key:
            node.right = self._insert(node.right, key, value)
        else:
            # chave já existe → substitui valor
            node.value = value
            return node

        # atualiza altura
        self._update_height(node)
        balance = self._balance_factor(node)

        # Casos de rotação
        # LL
        if balance > 1 and key < node.left.key:
            return self._rotate_right(node)

        # RR
        if balance < -1 and key > node.right.key:
            return self._rotate_left(node)

        # LR
        if balance > 1 and key > node.left.key:
            node.left = self._rotate_left(node.left)
            return self._rotate_right(node)

        # RL
        if balance < -1 and key < node.right.key:
            node.right = self._rotate_right(node.right)
            return self._rotate_left(node)

        return node

    # BUSCA PÚBLICA

    def search(self, key):
        """
        Busca uma chave na árvore.

        Args:
            key: chave procurada.

        Returns:
            (value, key) se encontrado, senão (None, None).
        """
        node = self._search_node(self.root, key)
        if node is None:
            return None, None
        return node.value, node.key

    def _search_node(self, node, key):
        """
        Busca recursiva interna.

        Args:
            node (AVLNode): nó atual.
            key: chave procurada.

        Returns:
            AVLNode ou None.
        """
        if node is None:
            return None
        if key == node.key:
            return node
        if key < node.key:
            return self._search_node(node.left, key)
        else:
            return self._search_node(node.right, key)

    # TRAVESSIA

    def inorder(self):
        """
        Retorna os elementos em ordem crescente de chave.

        Returns:
            list[(key, value)]: lista ordenada.
        """
        out = []

        def _in(n):
            if not n:
                return
            _in(n.left)
            out.append((n.key, n.value))
            _in(n.right)

        _in(self.root)
        return out
