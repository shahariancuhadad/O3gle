"""posts table

Revision ID: b1a98f23a941
Revises: fb3671131ae8
Create Date: 2023-02-23 17:23:20.311790

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1a98f23a941'
down_revision = 'fb3671131ae8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('screenshot',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('image_url', sa.String(length=64), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('screenshot', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_screenshot_timestamp'), ['timestamp'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('screenshot', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_screenshot_timestamp'))

    op.drop_table('screenshot')
    # ### end Alembic commands ###
